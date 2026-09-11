use anyhow::{Context, Result};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use super::flow::{queue_proxy_error, HttpMode, LocalFlow, LocalState, ProxyError, Step};
use super::{http, socks, DnsResolver, ProxyConfig, ProxyProtocol};
use crate::core::dns::{spawn_ipv4_query, DnsResult};
use crate::core::netstack::{
    receive_vpn, send_vpn, send_vpn_keepalive, IpTunnelDevice, VPN_KEEPALIVE_INTERVAL,
};
use crate::core::{protocol, util};

const TCP_BUFFER_SIZE: usize = 256 * 1024;
const LOCAL_WRITE_LIMIT: usize = 256 * 1024;
const DEFAULT_POLL: Duration = Duration::from_millis(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_BUFFER: usize = 16 * 1024;

pub(super) struct Engine<'a> {
    sock: &'a UdpSocket,
    listener: TcpListener,
    device: IpTunnelDevice,
    iface: Interface,
    sockets: SocketSet<'a>,
    flows: HashMap<u64, LocalFlow>,
    allocated_ports: HashSet<u16>,
    next_flow: u64,
    next_port: u16,
    dns: DnsResolver,
    dns_tx: Sender<DnsResult>,
    dns_rx: Receiver<DnsResult>,
    inner_ip: Ipv4Addr,
    protocol: ProxyProtocol,
    xor_key: &'a [u8],
    sid: u16,
    token: u32,
    encryption: u8,
    mtu: usize,
    session_started: StdInstant,
    last_keepalive: StdInstant,
}

impl<'a> Engine<'a> {
    pub(super) fn new(
        listener: TcpListener,
        sock: &'a UdpSocket,
        config: &ProxyConfig<'a>,
    ) -> Result<Self> {
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

        let (dns_tx, dns_rx) = mpsc::channel();
        let session_started = StdInstant::now();
        let last_keepalive = session_started
            .checked_sub(VPN_KEEPALIVE_INTERVAL)
            .unwrap_or(session_started);

        Ok(Self {
            sock,
            listener,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            allocated_ports: HashSet::new(),
            next_flow: 1,
            next_port: 49152,
            dns: config.dns.clone(),
            dns_tx,
            dns_rx,
            inner_ip: config.inner_ip,
            protocol: config.protocol,
            xor_key: config.xor_key,
            sid: config.sid,
            token: config.token,
            encryption: config.encryption,
            mtu: config.mtu,
            session_started,
            last_keepalive,
        })
    }

    pub(super) fn run(&mut self) -> Result<()> {
        let running = Arc::new(AtomicBool::new(true));
        let stop = running.clone();
        ctrlc::set_handler(move || stop.store(false, Ordering::Relaxed))
            .context("set SIGINT handler")?;

        while running.load(Ordering::Relaxed) {
            self.tick()?;

            let delay = self
                .iface
                .poll_delay(now(), &self.sockets)
                .map(|delay| Duration::from_millis(delay.total_millis()))
                .unwrap_or(DEFAULT_POLL)
                .min(DEFAULT_POLL);
            std::thread::sleep(delay);
        }

        for flow in self.flows.values_mut() {
            if let Some(handle) = flow.socket {
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
            }
        }
        self.iface.poll(now(), &mut self.device, &mut self.sockets);
        send_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.encryption,
        )?;
        let close = protocol::pkhdr(protocol::PT_CLOSE, self.encryption, self.sid, self.token);
        let _ = self.sock.send(&protocol::ctrl_pkt(&close, &[]));
        Ok(())
    }

    fn tick(&mut self) -> Result<()> {
        send_vpn_keepalive(
            self.sock,
            self.sid,
            self.token,
            self.encryption,
            &mut self.last_keepalive,
        )?;
        self.accept_clients()?;
        receive_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.mtu,
            self.encryption,
            self.session_started,
        )?;
        self.service_inputs();
        self.handle_dns_results();

        self.iface.poll(now(), &mut self.device, &mut self.sockets);
        self.update_tcp_states();
        self.service_outputs();
        send_vpn(
            self.sock,
            &mut self.device,
            self.xor_key,
            self.sid,
            self.token,
            self.encryption,
        )?;
        self.reap_flows();
        Ok(())
    }

    fn accept_clients(&mut self) -> Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    let id = self.next_flow;
                    self.next_flow = self.next_flow.wrapping_add(1);
                    self.flows
                        .insert(id, LocalFlow::new(stream, self.protocol)?);
                    if util::debug_enabled() {
                        eprintln!("[flow {id}] local client {peer}");
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e).context("accept local proxy client"),
            }
        }
    }

    fn service_inputs(&mut self) {
        let ids: Vec<u64> = self.flows.keys().copied().collect();
        for id in ids {
            if self.pump_input(id) {
                self.process_request(id);
            }
        }
    }

    /// Move bytes between the local socket and the userspace TCP socket.
    /// Returns true when the protocol handshake should run.
    fn pump_input(&mut self, id: u64) -> bool {
        let Some(flow) = self.flows.get_mut(&id) else {
            return false;
        };
        if flow.local_eof {
            return false;
        }

        if let Some(handle) = flow.socket {
            if matches!(flow.state, LocalState::Established) && !flow.input.is_empty() {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                let available = socket.send_capacity().saturating_sub(socket.send_queue());
                let count = available.min(flow.input.len());
                if count > 0 {
                    let sent = socket.send_slice(&flow.input[..count]).unwrap_or(0);
                    flow.input.drain(..sent);
                }
                if !flow.input.is_empty() {
                    return false;
                }
            }
        }

        let max_read = match flow.socket {
            Some(handle) if matches!(flow.state, LocalState::Established) => {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                socket.send_capacity().saturating_sub(socket.send_queue())
            }
            Some(_) => 0,
            None if flow.state.is_handshake() => READ_BUFFER,
            None => 0,
        };
        if max_read == 0 {
            return false;
        }

        let mut buf = [0u8; READ_BUFFER];
        let read_len = buf.len().min(max_read);
        match flow.stream.read(&mut buf[..read_len]) {
            Ok(0) => {
                flow.local_eof = true;
                if let Some(handle) = flow.socket {
                    self.sockets.get_mut::<tcp::Socket>(handle).close();
                    flow.set_state(LocalState::Closing);
                }
            }
            Ok(n) if flow.socket.is_none() => {
                flow.input.extend_from_slice(&buf[..n]);
                return true;
            }
            Ok(n) => {
                if let Some(handle) = flow.socket {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
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
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                    flow.set_state(LocalState::Closing);
                }
            }
        }
        false
    }

    fn process_request(&mut self, id: u64) {
        let step = {
            let Some(flow) = self.flows.get(&id) else {
                return;
            };
            match flow.state {
                LocalState::SocksGreeting => socks::greeting(&flow.input),
                LocalState::SocksRequest => socks::request(&flow.input),
                LocalState::HttpHead => http::request(&flow.input),
                _ => return,
            }
        };

        match step {
            Step::Wait => {}
            Step::Fail(error) => self.queue_error(id, error),
            Step::Reply {
                bytes,
                consumed,
                next,
            } => {
                if let Some(flow) = self.flows.get_mut(&id) {
                    flow.input.drain(..consumed);
                    flow.queue(&bytes);
                    flow.set_state(next);
                }
            }
            Step::Open {
                host,
                port,
                consumed,
                mode,
                rewritten,
            } => {
                if let Some(flow) = self.flows.get_mut(&id) {
                    flow.input.drain(..consumed);
                    if let Some(rewritten) = rewritten {
                        let mut input = rewritten;
                        input.extend_from_slice(&flow.input);
                        flow.input = input;
                    }
                    if let Some(mode) = mode {
                        flow.http_mode = Some(mode);
                    }
                }
                self.open_remote(id, &host, port);
            }
        }
    }

    fn handle_dns_results(&mut self) {
        while let Ok(answer) = self.dns_rx.try_recv() {
            let resolving = matches!(
                self.flows.get(&answer.flow_id),
                Some(flow) if matches!(flow.state, LocalState::Resolving)
            );
            if !resolving {
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
                    self.open_tcp_connection(answer.flow_id, remote, answer.port);
                }
                Err(()) => {
                    eprintln!(
                        "[flow {}] DNS {} failed via {}",
                        answer.flow_id, answer.domain, self.dns
                    );
                    if let Some(flow) = self.flows.get_mut(&answer.flow_id) {
                        queue_proxy_error(flow, self.protocol, ProxyError::HostUnreachable);
                    }
                }
            }
        }
    }

    fn update_tcp_states(&mut self) {
        for (id, flow) in self.flows.iter_mut() {
            let Some(handle) = flow.socket else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            match flow.state {
                LocalState::Connecting if socket.state() == tcp::State::Established => {
                    match self.protocol {
                        ProxyProtocol::Socks5 => {
                            let mut reply = vec![5, 0, 0, 1];
                            reply.extend_from_slice(&self.inner_ip.octets());
                            reply.extend_from_slice(&flow.local_port.to_be_bytes());
                            flow.queue(&reply);
                        }
                        ProxyProtocol::Http => {
                            if matches!(flow.http_mode, Some(HttpMode::Connect)) {
                                flow.queue(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                            }
                        }
                    }
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
                    queue_proxy_error(flow, self.protocol, ProxyError::ConnectionRefused);
                }
                LocalState::Connecting if flow.state_since.elapsed() >= CONNECT_TIMEOUT => {
                    eprintln!(
                        "[flow {id}] TCP connect timed out in state {:?}",
                        socket.state()
                    );
                    socket.abort();
                    queue_proxy_error(flow, self.protocol, ProxyError::GatewayTimeout);
                }
                _ => {}
            }
        }
    }

    fn service_outputs(&mut self) {
        for flow in self.flows.values_mut() {
            if flow.output.len() < LOCAL_WRITE_LIMIT {
                if let Some(handle) = flow.socket {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                    while socket.can_recv() && flow.output.len() < LOCAL_WRITE_LIMIT {
                        let room = LOCAL_WRITE_LIMIT - flow.output.len();
                        let mut buf = vec![0; room.min(READ_BUFFER)];
                        match socket.recv_slice(&mut buf) {
                            Ok(n) if n > 0 => flow.output.extend(&buf[..n]),
                            _ => break,
                        }
                    }
                }
            }

            while !flow.output.is_empty() {
                let (front, _) = flow.output.as_slices();
                match flow.stream.write(front) {
                    Ok(0) => break,
                    Ok(n) => {
                        flow.output.drain(..n);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        flow.local_eof = true;
                        if let Some(handle) = flow.socket {
                            self.sockets.get_mut::<tcp::Socket>(handle).abort();
                        }
                        flow.output.clear();
                        flow.set_state(LocalState::Closing);
                        break;
                    }
                }
            }

            if let Some(handle) = flow.socket {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                if remote_eof_ready(socket, flow.output.is_empty()) {
                    let _ = flow.stream.shutdown(Shutdown::Write);
                    socket.close();
                    flow.set_state(LocalState::Closing);
                }
            }
        }
    }

    fn reap_flows(&mut self) {
        reap_dead_flows(
            &mut self.flows,
            &mut self.sockets,
            &mut self.allocated_ports,
        );
    }

    fn open_remote(&mut self, id: u64, host: &str, port: u16) {
        match classify_host(host) {
            HostTarget::Ipv4(ip) => self.open_tcp_connection(id, ip, port),
            HostTarget::Ipv6 => self.queue_error(id, ProxyError::AddressNotSupported),
            HostTarget::Domain(name) => {
                if let Some(flow) = self.flows.get_mut(&id) {
                    flow.set_state(LocalState::Resolving);
                }
                spawn_ipv4_query(id, name, port, self.dns.clone(), self.dns_tx.clone());
            }
        }
    }

    fn open_tcp_connection(&mut self, id: u64, remote: Ipv4Addr, remote_port: u16) {
        let Some(local_port) = allocate_port(&self.allocated_ports, self.next_port) else {
            self.queue_error(id, ProxyError::GeneralFailure);
            return;
        };
        self.next_port = local_port.wrapping_add(1).max(49152);

        let rx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
        let tx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
        let mut socket = tcp::Socket::new(rx, tx);
        socket.set_timeout(Some(SmolDuration::from_secs(120)));
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(remote), remote_port);

        match socket.connect(self.iface.context(), endpoint, local_port) {
            Ok(()) => {
                self.allocated_ports.insert(local_port);
                let handle = self.sockets.add(socket);
                if let Some(flow) = self.flows.get_mut(&id) {
                    flow.socket = Some(handle);
                    flow.local_port = local_port;
                    flow.set_state(LocalState::Connecting);
                    if util::debug_enabled() {
                        eprintln!(
                            "[flow {id}] {}:{local_port} -> {remote}:{remote_port}",
                            self.inner_ip
                        );
                    }
                }
            }
            Err(_) => self.queue_error(id, ProxyError::GeneralFailure),
        }
    }

    fn queue_error(&mut self, id: u64, error: ProxyError) {
        if let Some(flow) = self.flows.get_mut(&id) {
            queue_proxy_error(flow, self.protocol, error);
        }
    }
}

enum HostTarget {
    Ipv4(Ipv4Addr),
    Ipv6,
    Domain(String),
}

fn classify_host(host: &str) -> HostTarget {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        HostTarget::Ipv4(ip)
    } else if host.contains(':') {
        HostTarget::Ipv6
    } else {
        HostTarget::Domain(host.to_string())
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

fn reap_dead_flows(
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
                None => {
                    (matches!(flow.state, LocalState::Closing) || flow.local_eof)
                        && flow.output.is_empty()
                }
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

fn remote_eof_ready(socket: &tcp::Socket<'_>, local_output_empty: bool) -> bool {
    socket.state() == tcp::State::CloseWait && !socket.can_recv() && local_output_empty
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
    fn classifies_host_targets() {
        assert!(matches!(classify_host("1.2.3.4"), HostTarget::Ipv4(_)));
        assert!(matches!(classify_host("2001:db8::1"), HostTarget::Ipv6));
        assert!(matches!(
            classify_host("example.com"),
            HostTarget::Domain(_)
        ));
    }

    #[test]
    fn reaps_socket_less_flows_after_local_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut flow = LocalFlow::new(client, ProxyProtocol::Http).unwrap();
        flow.local_eof = true;

        let mut flows = HashMap::new();
        flows.insert(7u64, flow);
        let mut sockets = SocketSet::new(vec![]);
        let mut allocated_ports = HashSet::new();
        reap_dead_flows(&mut flows, &mut sockets, &mut allocated_ports);
        assert!(flows.is_empty());
    }

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
