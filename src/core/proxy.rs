use super::{crypto, protocol, route, tun};
use anyhow::{Context, Result};
use std::net::{ToSocketAddrs, UdpSocket};
use std::os::fd::RawFd;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Run the TUN↔UDP data-plane pump. Blocks until Ctrl-C or error.
pub fn run_pump(
    tun_fd: RawFd,
    tun_name: &str,
    sock: &UdpSocket,
    xk: &[u8],
    sid: u16,
    tok: u32,
    enc: u8,
    server: &str,
    route_targets: &[String],
    auth_tun_ip: &str,
    auth_mtu: u16,
) -> Result<()> {
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

    let running = Arc::new(AtomicBool::new(true));
    let sock_send = sock.try_clone().context("clone send socket")?;
    let sock_recv = sock.try_clone().context("clone recv socket")?;
    sock_recv
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();

    let xk_send = xk.to_vec();
    let xk_recv = xk.to_vec();

    let r1 = running.clone();
    let t1 = std::thread::spawn(move || {
        const BATCH: usize = 64;
        const SLOT: usize = 2048;
        let mut buf_slots = vec![0u8; BATCH * SLOT];
        let mut iov:  [libc::iovec; BATCH]     = unsafe { std::mem::zeroed() };
        let mut mmsg: [libc::mmsghdr; BATCH]   = unsafe { std::mem::zeroed() };
        let hdr = protocol::pkhdr(protocol::PT_DATA_ENC, enc, sid, tok);

        for i in 0..BATCH {
            buf_slots[i * SLOT..i * SLOT + 8].copy_from_slice(&hdr);
            iov[i] = libc::iovec {
                iov_base: buf_slots[i * SLOT..].as_mut_ptr() as *mut _,
                iov_len:  0,
            };
            mmsg[i].msg_hdr.msg_iov    = &mut iov[i];
            mmsg[i].msg_hdr.msg_iovlen = 1;
        }

        let mut pfd = libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 };
        let mut cnt = 0usize;

        if super::util::debug_enabled() {
            eprintln!("[TUN→UDP] started");
        }
        loop {
            if !r1.load(Ordering::Relaxed) { break; }

            let s = &mut buf_slots[cnt * SLOT + 8..(cnt + 1) * SLOT];
            let n = tun::tun_read(tun_fd, s);

            if n > 0 {
                let n = n as usize;
                crypto::xor(&mut s[..n], &xk_send);
                iov[cnt].iov_len = n + 8;
                cnt += 1;
                if cnt == BATCH {
                    cnt = flush(&mut mmsg, cnt, sock_send.as_raw_fd());
                }
            } else if n == -1 {
                match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::WouldBlock => {
                        cnt = flush(&mut mmsg, cnt, sock_send.as_raw_fd());
                        unsafe { libc::poll(&mut pfd, 1, 200) };
                    }
                    std::io::ErrorKind::Interrupted => {}
                    _ => { r1.store(false, Ordering::Relaxed); break; }
                }
            } else {
                r1.store(false, Ordering::Relaxed);
                break;
            }
        }
        if super::util::debug_enabled() {
            eprintln!("[TUN→UDP] stopped");
        }
    });

    let r2 = running.clone();
    let t2 = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        let mut last_keepalive = Instant::now()
            .checked_sub(KEEPALIVE_INTERVAL)
            .unwrap_or_else(Instant::now);
        let keepalive_pkt = protocol::ctrl_pkt(
            &protocol::pkhdr(protocol::PT_ECHO_REQ, enc, sid, tok),
            &[],
        );
        let echo_res_pkt = protocol::ctrl_pkt(
            &protocol::pkhdr(protocol::PT_ECHO_RES, enc, sid, tok),
            &[],
        );
        if super::util::debug_enabled() {
            eprintln!("[UDP→TUN] started");
        }
        loop {
            if !r2.load(Ordering::Relaxed) {
                break;
            }
            if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                if let Err(e) = sock_recv.send(&keepalive_pkt) {
                    eprintln!("[UDP→TUN] keepalive send err: {e}");
                    r2.store(false, Ordering::Relaxed);
                    break;
                }
                last_keepalive = Instant::now();
            }
            match sock_recv.recv(&mut buf) {
                Ok(n) if n >= 8 => {
                    let t = buf[0];
                    if t == protocol::PT_DATA_ENC {
                        crypto::xor(&mut buf[8..n], &xk_recv);
                        tun::tun_write(tun_fd, &buf[8..n]);
                    } else if t == protocol::PT_DATA {
                        tun::tun_write(tun_fd, &buf[8..n]);
                    } else if t == protocol::PT_CLOSE {
                        eprintln!("[UDP→TUN] server sent CLOSE");
                        r2.store(false, Ordering::Relaxed);
                        break;
                    } else if t == protocol::PT_ECHO_REQ {
                        if let Err(e) = sock_recv.send(&echo_res_pkt) {
                            eprintln!("[UDP→TUN] keepalive response err: {e}");
                            r2.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[UDP→TUN] recv err: {e}");
                    r2.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        if super::util::debug_enabled() {
            eprintln!("[UDP→TUN] stopped");
        }
    });

    let rr = running.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nSIGINT — shutting down...");
        rr.store(false, Ordering::Relaxed);
    })
    .context("set SIGINT handler")?;

    println!("TUN proxy running — press Ctrl-C to stop");
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
    }
    t1.join().ok();
    t2.join().ok();

    if !routes.is_empty() {
        route::teardown(tun_name, server, &ogw, &odev, &routes);
    } else {
        let _ = super::util::ip_run(&["addr", "flush", "dev", tun_name]);
        let _ = super::util::ip_run(&["link", "set", tun_name, "down"]);
    }

    let c = protocol::pkhdr(protocol::PT_CLOSE, enc, sid, tok);
    let _ = sock.send(&protocol::ctrl_pkt(&c, &[]));
    if super::util::debug_enabled() {
        eprintln!("CLOSE sent");
    }
    Ok(())
}

fn flush(mmsg: &mut [libc::mmsghdr], cnt: usize, fd: std::os::fd::RawFd) -> usize {
    let mut off = 0usize;
    while off < cnt {
        let sent = unsafe {
            libc::sendmmsg(fd, mmsg.as_mut_ptr().add(off), (cnt - off) as _, 0)
        };
        if sent < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if super::util::debug_enabled() {
                let e = std::io::Error::last_os_error();
                eprintln!("[TUN→UDP] sendmmsg: {e}, drop {} pkts", cnt - off);
            }
            break;
        }
        off += sent as usize;
    }
    0
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
