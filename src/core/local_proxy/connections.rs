use anyhow::{Context, Result};
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use super::flow::{queue_proxy_error, HttpMode, LocalFlow, LocalState, ProxyError, Step};
use super::{http, socks, DnsResolver, ProxyConfig, ProxyProtocol};
use crate::core::dns::{spawn_ipv4_query, DnsResult};
use crate::core::netstack::IpTunnelDevice;
use crate::core::util;

const TCP_BUFFER_SIZE: usize = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The userspace TCP/IP stack: the smoltcp interface, its sockets and the
/// local proxy connections riding on them.
pub(super) struct Connections<'a> {
    listener: TcpListener,
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
}

impl<'a> Connections<'a> {
    pub(super) fn new(
        listener: TcpListener,
        mut iface: Interface,
        config: &ProxyConfig<'a>,
    ) -> Result<Self> {
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
        Ok(Self {
            listener,
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
        })
    }

    pub(super) fn poll(&mut self, device: &mut IpTunnelDevice, timestamp: Instant) {
        self.iface.poll(timestamp, device, &mut self.sockets);
    }

    pub(super) fn poll_delay(&mut self, timestamp: Instant) -> Option<Duration> {
        self.iface
            .poll_delay(timestamp, &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()))
    }

    pub(super) fn accept(&mut self) -> Result<()> {
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

    pub(super) fn service_inputs(&mut self) {
        let ids: Vec<u64> = self.flows.keys().copied().collect();
        for id in ids {
            let handshake = match self.flows.get_mut(&id) {
                Some(flow) => flow.pump_input(&mut self.sockets),
                None => false,
            };
            if handshake {
                self.process_request(id);
            }
        }
    }

    /// Apply the action a protocol front-end parsed from the handshake bytes.
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

    pub(super) fn handle_dns(&mut self) {
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

    pub(super) fn update_states(&mut self) {
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

    pub(super) fn service_outputs(&mut self) {
        for flow in self.flows.values_mut() {
            flow.service_outputs(&mut self.sockets);
        }
    }

    pub(super) fn reap(&mut self) {
        reap_dead_flows(
            &mut self.flows,
            &mut self.sockets,
            &mut self.allocated_ports,
        );
    }

    pub(super) fn abort_all(&mut self) {
        for flow in self.flows.values_mut() {
            if let Some(handle) = flow.socket {
                self.sockets.get_mut::<tcp::Socket>(handle).abort();
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::Config;
    use smoltcp::wire::HardwareAddress;
    use std::net::TcpStream;

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
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
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

        iface.poll(timestamp, &mut device, &mut sockets);
        let packet = device.pop_tx_packet().expect("TCP SYN packet");
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(packet[9], 6);
        assert_ne!(packet[20 + 13] & 0x02, 0);
    }
}
