use super::netstack::{
    receive_vpn, send_vpn, send_vpn_keepalive, spawn_ipv4_query, DnsResult, IpTunnelDevice,
    DNS_SERVER, VPN_KEEPALIVE_INTERVAL,
};
use super::{protocol, util};
use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

const TCP_BUFFER_SIZE: usize = 256 * 1024;
const LOCAL_WRITE_LIMIT: usize = 256 * 1024;
const DEFAULT_POLL: Duration = Duration::from_millis(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

enum LocalState {
    Greeting,
    Request,
    Resolving,
    Connecting,
    Established,
    Closing,
}

struct LocalFlow {
    stream: TcpStream,
    state: LocalState,
    input: Vec<u8>,
    output: VecDeque<u8>,
    socket: Option<SocketHandle>,
    local_port: u16,
    local_eof: bool,
    state_since: StdInstant,
}

impl LocalFlow {
    fn new(stream: TcpStream) -> Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream,
            state: LocalState::Greeting,
            input: Vec::new(),
            output: VecDeque::new(),
            socket: None,
            local_port: 0,
            local_eof: false,
            state_since: StdInstant::now(),
        })
    }

    fn queue(&mut self, bytes: &[u8]) {
        self.output.extend(bytes);
    }

    fn set_state(&mut self, state: LocalState) {
        self.state = state;
        self.state_since = StdInstant::now();
    }
}

/// Run a SOCKS5 listener backed by a smoltcp userspace TCP/IP stack.
///
/// `sock` must already be authenticated and connected to the VPN server.
pub struct SocksConfig<'a> {
    pub listen: SocketAddr,
    pub inner_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mtu: usize,
    pub xor_key: &'a [u8],
    pub sid: u16,
    pub token: u32,
    pub encryption: u8,
}

pub fn run(sock: &UdpSocket, config: SocksConfig<'_>) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .with_context(|| format!("bind SOCKS5 listener {}", config.listen))?;
    listener.set_nonblocking(true)?;
    sock.set_nonblocking(true)?;

    let mut device = IpTunnelDevice::new(config.mtu);
    let mut iface_config = Config::new(HardwareAddress::Ip);
    iface_config.random_seed = random_seed();
    let mut iface = Interface::new(iface_config, &mut device, now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(config.inner_ip), 24))
            .expect("IP address table full");
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(config.gateway)
        .context("add userspace default route")?;

    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: HashMap<u64, LocalFlow> = HashMap::new();
    let mut allocated_ports = HashSet::new();
    let mut next_flow = 1u64;
    let mut next_port = 49152u16;
    let (dns_tx, dns_rx) = mpsc::channel();
    let session_started = StdInstant::now();
    let mut last_keepalive = StdInstant::now()
        .checked_sub(VPN_KEEPALIVE_INTERVAL)
        .unwrap_or_else(StdInstant::now);
    let running = Arc::new(AtomicBool::new(true));
    let stop = running.clone();
    ctrlc::set_handler(move || stop.store(false, Ordering::Relaxed))
        .context("set SIGINT handler")?;

    println!("SOCKS5 listening on {}", config.listen);
    if util::debug_enabled() {
        eprintln!(
            "SOCKS5 network: IP {}, gateway {}, MTU {}",
            config.inner_ip, config.gateway, config.mtu
        );
    }

    while running.load(Ordering::Relaxed) {
        send_vpn_keepalive(
            sock,
            config.sid,
            config.token,
            config.encryption,
            &mut last_keepalive,
        )?;
        accept_connections(&listener, &mut flows, &mut next_flow)?;
        receive_vpn(
            sock,
            &mut device,
            config.xor_key,
            config.sid,
            config.token,
            config.mtu,
            config.encryption,
            session_started,
        )?;
        service_local_inputs(
            &mut flows,
            &mut sockets,
            &mut iface,
            config.inner_ip,
            &mut next_port,
            &mut allocated_ports,
            &dns_tx,
        );
        handle_dns_results(
            &dns_rx,
            &mut flows,
            &mut sockets,
            &mut iface,
            config.inner_ip,
            &mut next_port,
            &mut allocated_ports,
        );

        iface.poll(now(), &mut device, &mut sockets);
        update_tcp_states(&mut flows, &mut sockets, config.inner_ip);
        service_local_outputs(&mut flows, &mut sockets);
        send_vpn(
            sock,
            &mut device,
            config.xor_key,
            config.sid,
            config.token,
            config.encryption,
        )?;
        reap_flows(&mut flows, &mut sockets, &mut allocated_ports);

        let delay = iface
            .poll_delay(now(), &sockets)
            .map(|d| Duration::from_millis(d.total_millis()))
            .unwrap_or(DEFAULT_POLL)
            .min(DEFAULT_POLL);
        std::thread::sleep(delay);
    }

    for flow in flows.values_mut() {
        if let Some(handle) = flow.socket {
            sockets.get_mut::<tcp::Socket>(handle).abort();
        }
    }
    iface.poll(now(), &mut device, &mut sockets);
    send_vpn(
        sock,
        &mut device,
        config.xor_key,
        config.sid,
        config.token,
        config.encryption,
    )?;
    let close = protocol::pkhdr(
        protocol::PT_CLOSE,
        config.encryption,
        config.sid,
        config.token,
    );
    let _ = sock.send(&protocol::ctrl_pkt(&close, &[]));
    println!("SOCKS5 stopped");
    Ok(())
}

fn accept_connections(
    listener: &TcpListener,
    flows: &mut HashMap<u64, LocalFlow>,
    next_flow: &mut u64,
) -> Result<()> {
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                let id = *next_flow;
                *next_flow = next_flow.wrapping_add(1);
                flows.insert(id, LocalFlow::new(stream)?);
                if util::debug_enabled() {
                    eprintln!("[flow {id}] local client {peer}");
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("accept SOCKS5 client"),
        }
    }
}

fn service_local_inputs(
    flows: &mut HashMap<u64, LocalFlow>,
    sockets: &mut SocketSet<'_>,
    iface: &mut Interface,
    inner_ip: Ipv4Addr,
    next_port: &mut u16,
    allocated_ports: &mut HashSet<u16>,
    dns_tx: &Sender<DnsResult>,
) {
    let ids: Vec<u64> = flows.keys().copied().collect();
    for id in ids {
        let Some(flow) = flows.get_mut(&id) else {
            continue;
        };
        if flow.local_eof {
            continue;
        }

        if let Some(handle) = flow.socket {
            if matches!(flow.state, LocalState::Established) && !flow.input.is_empty() {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                let available = socket.send_capacity().saturating_sub(socket.send_queue());
                let count = available.min(flow.input.len());
                if count > 0 {
                    let sent = socket.send_slice(&flow.input[..count]).unwrap_or(0);
                    flow.input.drain(..sent);
                }
                if !flow.input.is_empty() {
                    continue;
                }
            }
        }

        let max_read = match flow.socket {
            Some(handle) if matches!(flow.state, LocalState::Established) => {
                let socket = sockets.get::<tcp::Socket>(handle);
                socket.send_capacity().saturating_sub(socket.send_queue())
            }
            Some(_) => 0,
            None if matches!(flow.state, LocalState::Greeting | LocalState::Request) => {
                buf_capacity()
            }
            None => 0,
        };
        if max_read == 0 {
            continue;
        }

        let mut buf = [0u8; 16 * 1024];
        let read_len = buf.len().min(max_read);
        match flow.stream.read(&mut buf[..read_len]) {
            Ok(0) => {
                flow.local_eof = true;
                if let Some(handle) = flow.socket {
                    sockets.get_mut::<tcp::Socket>(handle).close();
                    flow.set_state(LocalState::Closing);
                }
            }
            Ok(n) if flow.socket.is_none() => {
                flow.input.extend_from_slice(&buf[..n]);
                process_socks_handshake(
                    id,
                    flow,
                    sockets,
                    iface,
                    inner_ip,
                    next_port,
                    allocated_ports,
                    dns_tx,
                );
            }
            Ok(n) => {
                if let Some(handle) = flow.socket {
                    let socket = sockets.get_mut::<tcp::Socket>(handle);
                    let sent = socket.send_slice(&buf[..n]).unwrap_or(0);
                    if sent < n {
                        flow.input.extend_from_slice(&buf[sent..n]);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => {
                flow.local_eof = true;
                if let Some(handle) = flow.socket {
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    flow.set_state(LocalState::Closing);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_socks_handshake(
    id: u64,
    flow: &mut LocalFlow,
    sockets: &mut SocketSet<'_>,
    iface: &mut Interface,
    inner_ip: Ipv4Addr,
    next_port: &mut u16,
    allocated_ports: &mut HashSet<u16>,
    dns_tx: &Sender<DnsResult>,
) {
    if matches!(flow.state, LocalState::Greeting) {
        if flow.input.len() < 2 {
            return;
        }
        let methods = flow.input[1] as usize;
        if flow.input.len() < 2 + methods {
            return;
        }
        if flow.input[0] != 5 || !flow.input[2..2 + methods].contains(&0) {
            flow.queue(&[5, 0xff]);
            flow.set_state(LocalState::Closing);
            return;
        }
        flow.input.drain(..2 + methods);
        flow.queue(&[5, 0]);
        flow.set_state(LocalState::Request);
    }

    if !matches!(flow.state, LocalState::Request) || flow.input.len() < 4 {
        return;
    }
    if flow.input[0] != 5 || flow.input[1] != 1 {
        queue_socks_error(flow, 7);
        return;
    }
    let (remote, remote_port, consumed) = match flow.input[3] {
        1 => {
            if flow.input.len() < 10 {
                return;
            }
            (
                Some(Ipv4Addr::new(
                    flow.input[4],
                    flow.input[5],
                    flow.input[6],
                    flow.input[7],
                )),
                u16::from_be_bytes([flow.input[8], flow.input[9]]),
                10,
            )
        }
        3 => {
            if flow.input.len() < 5 {
                return;
            }
            let domain_len = flow.input[4] as usize;
            let request_len = 5 + domain_len + 2;
            if domain_len == 0 || flow.input.len() < request_len {
                return;
            }
            let Ok(domain) = std::str::from_utf8(&flow.input[5..5 + domain_len]) else {
                queue_socks_error(flow, 4);
                return;
            };
            let port = u16::from_be_bytes([flow.input[5 + domain_len], flow.input[6 + domain_len]]);
            let domain = domain.to_string();
            flow.input.drain(..request_len);
            flow.set_state(LocalState::Resolving);
            spawn_ipv4_query(id, domain, port, dns_tx.clone());
            return;
        }
        _ => {
            queue_socks_error(flow, 8);
            return;
        }
    };
    flow.input.drain(..consumed);
    open_tcp_connection(
        id,
        flow,
        sockets,
        iface,
        inner_ip,
        remote.expect("IPv4 request has an address"),
        remote_port,
        next_port,
        allocated_ports,
    );
}

#[allow(clippy::too_many_arguments)]
fn open_tcp_connection(
    id: u64,
    flow: &mut LocalFlow,
    sockets: &mut SocketSet<'_>,
    iface: &mut Interface,
    inner_ip: Ipv4Addr,
    remote: Ipv4Addr,
    remote_port: u16,
    next_port: &mut u16,
    allocated_ports: &mut HashSet<u16>,
) {
    let Some(local_port) = allocate_port(allocated_ports, *next_port) else {
        queue_socks_error(flow, 1);
        return;
    };
    *next_port = local_port.wrapping_add(1).max(49152);
    let rx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
    let tx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_timeout(Some(SmolDuration::from_secs(120)));
    let endpoint = IpEndpoint::new(IpAddress::Ipv4(remote), remote_port);
    match socket.connect(iface.context(), endpoint, local_port) {
        Ok(()) => {
            allocated_ports.insert(local_port);
            let handle = sockets.add(socket);
            flow.socket = Some(handle);
            flow.local_port = local_port;
            flow.set_state(LocalState::Connecting);
            if util::debug_enabled() {
                eprintln!("[flow {id}] {inner_ip}:{local_port} -> {remote}:{remote_port}");
            }
        }
        Err(_) => queue_socks_error(flow, 1),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_dns_results(
    receiver: &Receiver<DnsResult>,
    flows: &mut HashMap<u64, LocalFlow>,
    sockets: &mut SocketSet<'_>,
    iface: &mut Interface,
    inner_ip: Ipv4Addr,
    next_port: &mut u16,
    allocated_ports: &mut HashSet<u16>,
) {
    while let Ok(answer) = receiver.try_recv() {
        let Some(flow) = flows.get_mut(&answer.flow_id) else {
            continue;
        };
        if !matches!(flow.state, LocalState::Resolving) {
            continue;
        }
        match answer.result {
            Ok(remote) => {
                if util::debug_enabled() {
                    eprintln!(
                        "[flow {}] DNS {} -> {}",
                        answer.flow_id, answer.domain, remote
                    );
                }
                open_tcp_connection(
                    answer.flow_id,
                    flow,
                    sockets,
                    iface,
                    inner_ip,
                    remote,
                    answer.port,
                    next_port,
                    allocated_ports,
                )
            }
            Err(()) => {
                eprintln!(
                    "[flow {}] DNS {} failed via {}",
                    answer.flow_id, answer.domain, DNS_SERVER
                );
                queue_socks_error(flow, 4);
            }
        }
    }
}

fn allocate_port(allocated: &HashSet<u16>, start: u16) -> Option<u16> {
    let mut candidate = start.max(49152);
    for _ in 49152..=u16::MAX {
        if !allocated.contains(&candidate) {
            return Some(candidate);
        }
        candidate = candidate.wrapping_add(1).max(49152);
    }
    None
}

fn buf_capacity() -> usize {
    16 * 1024
}

fn update_tcp_states(
    flows: &mut HashMap<u64, LocalFlow>,
    sockets: &mut SocketSet<'_>,
    inner_ip: Ipv4Addr,
) {
    for (id, flow) in flows.iter_mut() {
        let Some(handle) = flow.socket else {
            continue;
        };
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        match flow.state {
            LocalState::Connecting if socket.state() == tcp::State::Established => {
                let mut reply = vec![5, 0, 0, 1];
                reply.extend_from_slice(&inner_ip.octets());
                reply.extend_from_slice(&flow.local_port.to_be_bytes());
                flow.queue(&reply);
                flow.set_state(LocalState::Established);
                if util::debug_enabled() {
                    eprintln!("[flow {id}] TCP established");
                }
            }
            LocalState::Connecting
                if matches!(
                    socket.state(),
                    tcp::State::Closed | tcp::State::CloseWait | tcp::State::TimeWait
                ) =>
            {
                eprintln!(
                    "[flow {id}] TCP connect failed in state {:?}",
                    socket.state()
                );
                queue_socks_error(flow, 5);
            }
            LocalState::Connecting if flow.state_since.elapsed() >= CONNECT_TIMEOUT => {
                eprintln!(
                    "[flow {id}] TCP connect timed out in state {:?}",
                    socket.state()
                );
                socket.abort();
                queue_socks_error(flow, 4);
            }
            _ => {}
        }
    }
}

fn service_local_outputs(flows: &mut HashMap<u64, LocalFlow>, sockets: &mut SocketSet<'_>) {
    for flow in flows.values_mut() {
        if flow.output.len() < LOCAL_WRITE_LIMIT {
            if let Some(handle) = flow.socket {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                while socket.can_recv() && flow.output.len() < LOCAL_WRITE_LIMIT {
                    let room = LOCAL_WRITE_LIMIT - flow.output.len();
                    let mut buf = vec![0; room.min(16 * 1024)];
                    match socket.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => flow.output.extend(&buf[..n]),
                        _ => break,
                    }
                }
            }
        }

        while !flow.output.is_empty() {
            let (a, _) = flow.output.as_slices();
            match flow.stream.write(a) {
                Ok(0) => break,
                Ok(n) => {
                    flow.output.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    flow.local_eof = true;
                    if let Some(handle) = flow.socket {
                        sockets.get_mut::<tcp::Socket>(handle).abort();
                    }
                    flow.output.clear();
                    flow.set_state(LocalState::Closing);
                    break;
                }
            }
        }

        if let Some(handle) = flow.socket {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if remote_eof_ready(socket, flow.output.is_empty()) {
                let _ = flow.stream.shutdown(Shutdown::Write);
                socket.close();
                flow.set_state(LocalState::Closing);
            }
        }
    }
}

fn remote_eof_ready(socket: &tcp::Socket<'_>, local_output_empty: bool) -> bool {
    socket.state() == tcp::State::CloseWait && !socket.can_recv() && local_output_empty
}

fn reap_flows(
    flows: &mut HashMap<u64, LocalFlow>,
    sockets: &mut SocketSet<'_>,
    allocated_ports: &mut HashSet<u16>,
) {
    let dead: Vec<u64> = flows
        .iter()
        .filter_map(|(id, flow)| {
            let removable = match flow.socket {
                Some(handle) => {
                    sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed
                        && flow.output.is_empty()
                }
                None => matches!(flow.state, LocalState::Closing) && flow.output.is_empty(),
            };
            removable.then_some(*id)
        })
        .collect();
    for id in dead {
        if let Some(flow) = flows.remove(&id) {
            allocated_ports.remove(&flow.local_port);
            if let Some(handle) = flow.socket {
                sockets.remove(handle);
            }
        }
        if util::debug_enabled() {
            eprintln!("[flow {id}] closed");
        }
    }
}

fn queue_socks_error(flow: &mut LocalFlow, rep: u8) {
    flow.queue(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]);
    flow.set_state(LocalState::Closing);
}

fn now() -> Instant {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64;
    Instant::from_millis(millis)
}

fn random_seed() -> u64 {
    use rand::RngCore;
    rand::thread_rng().next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userspace_stack_emits_an_ipv4_tcp_syn() {
        let mut device = IpTunnelDevice::new(1380);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 1;
        let timestamp = Instant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, timestamp);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(10, 8, 0, 2)), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(100, 100, 1, 1))
            .unwrap();

        let rx = tcp::SocketBuffer::new(vec![0; 4096]);
        let tx = tcp::SocketBuffer::new(vec![0; 4096]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket
            .connect(
                iface.context(),
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 443),
                49152,
            )
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let handle = sockets.add(socket);
        let connecting = sockets.get::<tcp::Socket>(handle);
        assert_eq!(connecting.state(), tcp::State::SynSent);
        assert!(!remote_eof_ready(connecting, true));

        iface.poll(timestamp, &mut device, &mut sockets);
        let packet = device.pop_tx_packet().expect("TCP SYN packet");
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(packet[9], 6);
        assert_ne!(packet[20 + 13] & 0x02, 0);
    }
}
