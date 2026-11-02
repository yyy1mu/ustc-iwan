use super::{
    protocol, route,
    sr::SrConfig,
    tun,
    tunnel::{encode_sr_echo, encode_uplink, encode_uplink_sr, TunnelRx},
};
use anyhow::{Context, Result};
use std::net::{Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Upload batching: each TUN packet occupies one SLOT plus the 8-byte
/// protocol header, so the negotiated MTU must satisfy mtu + 8 <= SLOT.
const BATCH: usize = 64;
const SLOT: usize = 9216;
const HEADER: usize = 8;

static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn shutdown_flag() -> Arc<AtomicBool> {
    SHUTDOWN
        .get_or_init(|| {
            let flag = Arc::new(AtomicBool::new(false));
            let handler_flag = flag.clone();
            let _ = ctrlc::set_handler(move || {
                eprintln!("\nSIGINT — shutting down...");
                handler_flag.store(true, Ordering::Relaxed);
            });
            flag
        })
        .clone()
}

/// A batch of TUN packets with protocol headers, flushed to the server
/// with one `sendmmsg` call.
struct UploadBatch {
    slots: Vec<u8>,
    iov: Box<[libc::iovec; BATCH]>,
    mmsg: Box<[libc::mmsghdr; BATCH]>,
    count: usize,
    fd: RawFd,
}

impl UploadBatch {
    fn new(fd: RawFd) -> Self {
        let mut slots = vec![0u8; BATCH * SLOT];
        let mut iov: Box<[libc::iovec; BATCH]> = Box::new(unsafe { std::mem::zeroed() });
        let mut mmsg: Box<[libc::mmsghdr; BATCH]> = Box::new(unsafe { std::mem::zeroed() });
        for i in 0..BATCH {
            iov[i] = libc::iovec {
                iov_base: slots[i * SLOT..].as_mut_ptr() as *mut _,
                iov_len: 0,
            };
            mmsg[i].msg_hdr.msg_iov = &mut iov[i];
            mmsg[i].msg_hdr.msg_iovlen = 1;
        }
        Self {
            slots,
            iov,
            mmsg,
            count: 0,
            fd,
        }
    }

    /// Writable payload area of the next slot, excluding the protocol header.
    fn slot(&mut self) -> &mut [u8] {
        &mut self.slots[self.count * SLOT + HEADER..(self.count + 1) * SLOT]
    }

    fn queue(&mut self, header: &[u8; HEADER], len: usize) {
        let base = self.count * SLOT;
        self.slots[base..base + HEADER].copy_from_slice(header);
        self.iov[self.count].iov_len = len + HEADER;
        self.count += 1;
    }

    fn queue_duplicate(&mut self, header: &[u8; HEADER], len: usize) {
        if self.count == 0 || self.count >= BATCH {
            return;
        }
        let base = self.count * SLOT;
        let prev = (self.count - 1) * SLOT;
        let total = HEADER + len;
        self.slots.copy_within(prev..prev + total, base);
        self.slots[base..base + HEADER].copy_from_slice(header);
        self.iov[self.count].iov_len = total;
        self.count += 1;
    }

    fn queue_packet(&mut self, packet: &[u8]) {
        if packet.len() > SLOT {
            eprintln!(
                "[TUN→UDP] drop oversized packet: {} > {} bytes",
                packet.len(),
                SLOT
            );
            return;
        }
        let base = self.count * SLOT;
        self.slots[base..base + packet.len()].copy_from_slice(packet);
        self.iov[self.count].iov_len = packet.len();
        self.count += 1;
    }

    fn is_full(&self) -> bool {
        self.count == BATCH
    }

    fn flush(&mut self) {
        let mut off = 0usize;
        while off < self.count {
            let sent = unsafe {
                libc::sendmmsg(
                    self.fd,
                    self.mmsg.as_mut_ptr().add(off),
                    (self.count - off) as _,
                    0,
                )
            };
            if sent < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if super::util::debug_enabled() {
                    let e = std::io::Error::last_os_error();
                    eprintln!("[TUN→UDP] sendmmsg: {e}, drop {} pkts", self.count - off);
                }
                break;
            }
            if sent == 0 {
                // A blocking UDP socket should always send at least one message;
                // bail out instead of spinning if the kernel ever reports zero.
                if super::util::debug_enabled() {
                    eprintln!("[TUN→UDP] sendmmsg sent 0, drop {} pkts", self.count - off);
                }
                break;
            }
            off += sent as usize;
        }
        self.count = 0;
    }
}

/// Options for the TUN↔UDP data-plane pump.
pub struct PumpConfig<'a> {
    pub tun_fd: RawFd,
    pub tun_name: &'a str,
    pub sock: &'a UdpSocket,
    pub xor_key: &'a [u8],
    pub aes_key: &'a [u8],
    pub sid: u16,
    pub token: u32,
    pub encryption: u8,
    pub server: &'a str,
    pub route_targets: &'a [String],
    pub tun_ip: &'a str,
    pub tun_ipv6: Option<Ipv6Addr>,
    pub mtu: u16,
    pub sr: Option<SrConfig>,
    pub duplicate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PumpOutcome {
    Stopped,
    ServerClosed,
}

/// Run the TUN↔UDP data-plane pump. Blocks until Ctrl-C or error.
pub fn run_pump(config: PumpConfig<'_>) -> Result<PumpOutcome> {
    let PumpConfig {
        tun_fd,
        tun_name,
        sock,
        xor_key: xk,
        aes_key,
        sid,
        token: tok,
        encryption: enc,
        server,
        route_targets,
        tun_ip: auth_tun_ip,
        tun_ipv6: auth_tun_ipv6,
        mtu: auth_mtu,
        sr,
        duplicate,
    } = config;
    anyhow::ensure!(
        usize::from(auth_mtu) + HEADER <= SLOT,
        "TUN MTU {} exceeds the {}-byte upload slot limit",
        auth_mtu,
        SLOT - HEADER
    );
    let (ogw, odev) = route::capture_default().context("cannot detect default route")?;
    if super::util::debug_enabled() {
        eprintln!("default route: via {ogw} dev {odev}");
    }

    let routes = expand_route_targets(route_targets)?;
    if !routes.is_empty() {
        route::setup(
            tun_name,
            auth_tun_ip,
            auth_mtu,
            server,
            &ogw,
            &odev,
            &routes,
        );
        println!(
            "TUN {tun_name} ready: {} route{}",
            routes.len(),
            if routes.len() == 1 { "" } else { "s" }
        );
        if super::util::debug_enabled() {
            for route in &routes {
                eprintln!("route {route} -> dev {tun_name}");
            }
        }
    } else {
        let _ = super::util::ip_run(&["addr", "flush", "dev", tun_name]);
        super::util::ip_run(&["link", "set", tun_name, "up"]);
        super::util::ip_run(&["link", "set", "dev", tun_name, "mtu", &auth_mtu.to_string()]);
        super::util::ip_run(&["addr", "add", &format!("{auth_tun_ip}/24"), "dev", tun_name]);
        println!("tun {tun_name} up with IP {auth_tun_ip}/24 (no route hijack)");
    }
    if let Some(ipv6) = auth_tun_ipv6 {
        super::util::ip_run(&["-6", "addr", "add", &format!("{ipv6}/64"), "dev", tun_name]);
        if super::util::debug_enabled() {
            eprintln!("tun {tun_name} IPv6 {ipv6}/64");
        }
    }

    let shutdown = shutdown_flag();
    let running = Arc::new(AtomicBool::new(true));
    let server_closed = Arc::new(AtomicBool::new(false));
    let sock_send = sock.try_clone().context("clone send socket")?;
    let sock_recv = sock.try_clone().context("clone recv socket")?;
    sock_recv
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();

    let xk_send = xk.to_vec();
    let xk_recv = xk.to_vec();
    let aes_send = aes_key.to_vec();
    let aes_recv = aes_key.to_vec();

    let sr_tx = sr.clone();
    let r1 = running.clone();
    let shutdown_tx = shutdown.clone();
    let t1 = std::thread::spawn(move || {
        let mut batch = UploadBatch::new(sock_send.as_raw_fd());
        let mut pfd = libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        if super::util::debug_enabled() {
            eprintln!("[TUN→UDP] started");
        }
        loop {
            if !r1.load(Ordering::Relaxed) || shutdown_tx.load(Ordering::Relaxed) {
                break;
            }

            let n = tun::tun_read(tun_fd, batch.slot());
            if n > 0 {
                let n = n as usize;
                if let Some(sr) = &sr_tx {
                    let slot = batch.slot();
                    match encode_uplink_sr(slot, &xk_send, &aes_send, sid, tok, enc, sr) {
                        Ok(packet) => {
                            batch.queue_packet(&packet);
                            if duplicate {
                                batch.queue_packet(&packet);
                            }
                        }
                        Err(e) => {
                            if super::util::debug_enabled() {
                                eprintln!("[TUN→UDP] drop SR packet: {e}");
                            }
                            continue;
                        }
                    }
                } else {
                    let (header, wire_len) = {
                        let slot = batch.slot();
                        match encode_uplink(slot, n, &xk_send, &aes_send, sid, tok, enc) {
                            Ok(value) => value,
                            Err(e) => {
                                if super::util::debug_enabled() {
                                    eprintln!("[TUN→UDP] drop invalid packet: {e}");
                                }
                                continue;
                            }
                        }
                    };
                    batch.queue(&header, wire_len);
                    if duplicate {
                        let mut dup_header = header;
                        dup_header[0] = match header[0] {
                            protocol::PT_DATA => protocol::PT_DATA_DUP,
                            protocol::PT_DATA_ENC => protocol::PT_DATA_ENC_DUP,
                            other => other,
                        };
                        batch.queue_duplicate(&dup_header, wire_len);
                    }
                }
                if batch.is_full() {
                    batch.flush();
                }
            } else if n == -1 {
                match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::WouldBlock => {
                        batch.flush();
                        unsafe { libc::poll(&mut pfd, 1, 200) };
                    }
                    std::io::ErrorKind::Interrupted => {}
                    _ => {
                        r1.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            } else {
                r1.store(false, Ordering::Relaxed);
                break;
            }
        }
        batch.flush();
        if super::util::debug_enabled() {
            eprintln!("[TUN→UDP] stopped");
        }
    });

    let r2 = running.clone();
    let shutdown_rx = shutdown.clone();
    let closed = server_closed.clone();
    let sr_monitor = sr.clone();
    let t2 = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        let mut rx = TunnelRx::new(&xk_recv, &aes_recv, enc, sid, tok, sr);
        let mut last_keepalive = Instant::now()
            .checked_sub(KEEPALIVE_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_sr_echo = Instant::now();
        let mut last_echo_response = Instant::now();
        if super::util::debug_enabled() {
            eprintln!("[UDP→TUN] started");
        }
        loop {
            if !r2.load(Ordering::Relaxed) || shutdown_rx.load(Ordering::Relaxed) {
                break;
            }
            if last_echo_response.elapsed() > KEEPALIVE_TIMEOUT {
                eprintln!("[UDP→TUN] keepalive timeout");
                closed.store(true, Ordering::Relaxed);
                r2.store(false, Ordering::Relaxed);
                break;
            }
            if let Some(sr) = &sr_monitor {
                if last_sr_echo.elapsed() >= Duration::from_secs(5) {
                    let payload = super::sr::monitor_payload(sr.local_id, 0, 0);
                    if let Err(e) = sock_recv.send(&encode_sr_echo(sr, sid, tok, &payload)) {
                        eprintln!("[UDP→TUN] SR echo send err: {e}");
                        closed.store(true, Ordering::Relaxed);
                        r2.store(false, Ordering::Relaxed);
                        break;
                    }
                    last_sr_echo = Instant::now();
                }
            }
            if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                let mut payload = vec![0u8; 36];
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;
                payload[..8].copy_from_slice(&now.to_le_bytes());
                let header = protocol::pkhdr(protocol::PT_ECHO_REQ, enc, sid, tok);
                if let Err(e) = sock_recv.send(&protocol::ctrl_pkt(&header, &payload)) {
                    eprintln!("[UDP→TUN] keepalive send err: {e}");
                    r2.store(false, Ordering::Relaxed);
                    break;
                }
                last_keepalive = Instant::now();
            }
            match sock_recv.recv(&mut buf) {
                Ok(n) if n >= 8 => match buf[0] {
                    protocol::PT_CLOSE => {
                        eprintln!("[UDP→TUN] server sent CLOSE");
                        closed.store(true, Ordering::Relaxed);
                        r2.store(false, Ordering::Relaxed);
                        break;
                    }
                    protocol::PT_ECHO_REQ => {
                        let payload = buf.get(24..n).unwrap_or(&[]);
                        let header = protocol::pkhdr(protocol::PT_ECHO_RES, buf[1], sid, tok);
                        if let Err(e) = sock_recv.send(&protocol::ctrl_pkt(&header, payload)) {
                            eprintln!("[UDP→TUN] keepalive response err: {e}");
                            closed.store(true, Ordering::Relaxed);
                            r2.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                    protocol::PT_ECHO_RES => {
                        last_keepalive = Instant::now();
                        last_echo_response = Instant::now();
                    }
                    protocol::PT_DATA
                    | protocol::PT_DATA_ENC
                    | protocol::PT_DATA_IPV6
                    | protocol::PT_IPFRAG
                    | protocol::PT_IPFRAG_ALT
                    | protocol::PT_SEGRT => {
                        if let Err(e) = rx.handle(&buf[..n], &mut |packet| {
                            tun::tun_write(tun_fd, packet);
                        }) {
                            if super::util::debug_enabled() {
                                eprintln!("[UDP→TUN] packet error: {e}");
                            }
                        }
                    }
                    _ => {}
                },
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[UDP→TUN] recv err: {e}");
                    closed.store(true, Ordering::Relaxed);
                    r2.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        if super::util::debug_enabled() {
            eprintln!("[UDP→TUN] stopped");
        }
    });

    println!("TUN proxy running — press Ctrl-C to stop");
    let mut last_net_check = Instant::now();
    while running.load(Ordering::Relaxed) && !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        if last_net_check.elapsed() >= Duration::from_secs(5) {
            last_net_check = Instant::now();
            if let Some((gw, dev)) = route::capture_default() {
                if dev != tun_name && (gw != ogw || dev != odev) {
                    eprintln!("default route changed: {ogw}/{odev} -> {gw}/{dev}; reconnecting...");
                    server_closed.store(true, Ordering::Relaxed);
                    running.store(false, Ordering::Relaxed);
                }
            }
        }
    }
    running.store(false, Ordering::Relaxed);
    t1.join().ok();
    t2.join().ok();

    if !routes.is_empty() {
        route::teardown(tun_name, server, &ogw, &odev, &routes);
    } else {
        let _ = super::util::ip_run(&["addr", "flush", "dev", tun_name]);
    }
    let _ = super::util::ip_run(&["-6", "addr", "flush", "dev", tun_name]);
    let _ = super::util::ip_run(&["link", "set", tun_name, "down"]);

    let c = protocol::pkhdr(protocol::PT_CLOSE, enc, sid, tok);
    let _ = sock.send(&protocol::ctrl_pkt(&c, &[]));
    if super::util::debug_enabled() {
        eprintln!("CLOSE sent");
    }
    if server_closed.load(Ordering::Relaxed) {
        Ok(PumpOutcome::ServerClosed)
    } else {
        Ok(PumpOutcome::Stopped)
    }
}

fn expand_route_targets(targets: &[String]) -> Result<Vec<String>> {
    let mut routes = Vec::new();
    for target in targets {
        let target = target.trim();
        if target.is_empty() {
            continue;
        }
        if target == "default" || target.contains('/') {
            push_unique(&mut routes, target.to_string());
        } else if target.parse::<std::net::Ipv4Addr>().is_ok() {
            push_unique(&mut routes, format!("{target}/32"));
        } else {
            let mut found = false;
            for addr in (target, 0)
                .to_socket_addrs()
                .with_context(|| format!("resolve domain {target}"))?
            {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    push_unique(&mut routes, format!("{ip}/32"));
                    found = true;
                }
            }
            if !found {
                anyhow::bail!("domain has no IPv4 address: {target}");
            }
        }
    }
    Ok(routes)
}

fn push_unique(routes: &mut Vec<String>, route: String) {
    if !routes.iter().any(|r| r == &route) {
        routes.push(route);
    }
}
