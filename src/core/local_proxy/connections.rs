use anyhow::{Context, Result};
use smoltcp::iface::{Interface, SocketSet};
use smoltcp::socket::{tcp, udp as smol_udp};
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant as StdInstant};

use super::flow::{queue_proxy_error, HttpMode, LocalFlow, LocalState, ProxyError, Step};
use super::{http, socks, udp, DnsResolver, ProxyConfig, ProxyProtocol};
use crate::core::dns::{spawn_ipv4_query, DnsResult};
use crate::core::netstack::IpTunnelDevice;
use crate::core::util;

const TCP_BUFFER_SIZE: usize = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IPV4_UDP_HEADER_SIZE: usize = 28;
const UDP_BURST_LIMIT: usize = 64;

enum DnsContext {
    Tcp { flow_id: u64, port: u16 },
    Udp,
}

struct PendingUdpDatagram {
    flow_id: u64,
    port: u16,
    payload: Vec<u8>,
}

struct CachedDns {
    address: Ipv4Addr,
    expires_at: StdInstant,
}

/// The userspace TCP/IP stack: the smoltcp interface, its sockets and the
/// local proxy connections riding on them.
pub(super) struct Connections<'a> {
    listener: TcpListener,
    iface: Interface,
    sockets: SocketSet<'a>,
    flows: HashMap<u64, LocalFlow>,
    udp_associations: HashMap<u64, udp::Association>,
    allocated_ports: HashSet<u16>,
    next_flow: u64,
    next_port: u16,
    dns: DnsResolver,
    dns_tx: Sender<DnsResult<DnsContext>>,
    dns_rx: Receiver<DnsResult<DnsContext>>,
    pending_udp_dns: HashMap<String, Vec<PendingUdpDatagram>>,
    udp_dns_cache: HashMap<String, CachedDns>,
    inner_ip: Ipv4Addr,
    max_udp_payload: usize,
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
            udp_associations: HashMap::new(),
            allocated_ports: HashSet::new(),
            next_flow: 1,
            next_port: 49152,
            dns: config.dns.clone(),
            dns_tx,
            dns_rx,
            pending_udp_dns: HashMap::new(),
            udp_dns_cache: HashMap::new(),
            inner_ip: config.inner_ip,
            max_udp_payload: config.mtu.saturating_sub(IPV4_UDP_HEADER_SIZE),
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
            Step::UdpAssociate {
                client_port,
                consumed,
            } => {
                if let Some(flow) = self.flows.get_mut(&id) {
                    flow.input.drain(..consumed);
                    flow.input.clear();
                }
                self.open_udp_association(id, client_port);
            }
        }
    }

    pub(super) fn handle_dns(&mut self) {
        while let Ok(response) = self.dns_rx.try_recv() {
            match response.context {
                DnsContext::Tcp { flow_id, port } => {
                    let resolving = matches!(
                        self.flows.get(&flow_id),
                        Some(flow) if matches!(flow.state, LocalState::Resolving)
                    );
                    if !resolving {
                        continue;
                    }
                    match response.result {
                        Ok(answer) => {
                            if util::debug_enabled() {
                                eprintln!(
                                    "[flow {flow_id}] DNS {} -> {}",
                                    response.domain, answer.address
                                );
                            }
                            self.open_tcp_connection(flow_id, answer.address, port);
                        }
                        Err(()) => {
                            eprintln!(
                                "[flow {flow_id}] DNS {} failed via {}",
                                response.domain, self.dns
                            );
                            if let Some(flow) = self.flows.get_mut(&flow_id) {
                                queue_proxy_error(flow, self.protocol, ProxyError::HostUnreachable);
                            }
                        }
                    }
                }
                DnsContext::Udp => {
                    let domain = response.domain.trim_end_matches('.').to_ascii_lowercase();
                    let pending = self.pending_udp_dns.remove(&domain).unwrap_or_default();
                    match response.result {
                        Ok(resolved) => {
                            if !resolved.ttl.is_zero() {
                                self.udp_dns_cache.insert(
                                    domain,
                                    CachedDns {
                                        address: resolved.address,
                                        expires_at: StdInstant::now() + resolved.ttl,
                                    },
                                );
                            }
                            for datagram in pending {
                                self.send_udp_datagram(
                                    datagram.flow_id,
                                    resolved.address,
                                    datagram.port,
                                    &datagram.payload,
                                );
                            }
                        }
                        Err(()) if util::debug_enabled() => {
                            eprintln!("UDP target DNS {} failed via {}", response.domain, self.dns)
                        }
                        Err(()) => {}
                    }
                }
            }
        }
    }

    pub(super) fn service_udp_inputs(&mut self) {
        let mut received = Vec::new();
        for (id, association) in self.udp_associations.iter_mut() {
            for _ in 0..UDP_BURST_LIMIT {
                match association.receive(self.max_udp_payload) {
                    Ok(Some(datagram)) => received.push((*id, datagram)),
                    Ok(None) => break,
                    Err(error) => {
                        eprintln!("[flow {id}] UDP relay receive failed: {error:#}");
                        if let Some(flow) = self.flows.get_mut(id) {
                            flow.set_state(LocalState::Closing);
                        }
                        break;
                    }
                }
            }
        }

        for (flow_id, datagram) in received {
            match datagram.target {
                udp::Target::Ipv4(remote, port) => {
                    self.send_udp_datagram(flow_id, remote, port, &datagram.payload)
                }
                udp::Target::Domain(domain, port) => {
                    self.resolve_udp_domain(flow_id, domain, port, datagram.payload)
                }
            }
        }
    }

    pub(super) fn service_udp_outputs(&mut self) {
        for (id, association) in self.udp_associations.iter_mut() {
            for _ in 0..UDP_BURST_LIMIT {
                let socket = self
                    .sockets
                    .get_mut::<smol_udp::Socket>(association.tunnel_handle());
                match socket.recv() {
                    Ok((payload, metadata)) => {
                        if let Err(error) = association.send_response(metadata.endpoint, payload) {
                            eprintln!("[flow {id}] UDP relay send failed: {error:#}");
                            break;
                        }
                    }
                    Err(_) => break,
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
            &mut self.udp_associations,
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
        for association in self.udp_associations.values() {
            self.sockets
                .get_mut::<smol_udp::Socket>(association.tunnel_handle())
                .close();
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
                spawn_ipv4_query(
                    name,
                    self.dns.clone(),
                    DnsContext::Tcp { flow_id: id, port },
                    self.dns_tx.clone(),
                );
            }
        }
    }

    fn open_udp_association(&mut self, id: u64, requested_port: u16) {
        let Some(local_port) = allocate_port(&self.allocated_ports, self.next_port) else {
            self.queue_error(id, ProxyError::GeneralFailure);
            return;
        };
        if self.max_udp_payload == 0 {
            self.queue_error(id, ProxyError::GeneralFailure);
            return;
        }
        let socket = match udp::new_tunnel_socket(local_port, self.max_udp_payload) {
            Ok(socket) => socket,
            Err(error) => {
                eprintln!("[flow {id}] create UDP socket failed: {error:#}");
                self.queue_error(id, ProxyError::GeneralFailure);
                return;
            }
        };
        let tunnel_handle = self.sockets.add(socket);
        let association = {
            let Some(flow) = self.flows.get(&id) else {
                self.sockets.remove(tunnel_handle);
                return;
            };
            udp::Association::bind(&flow.stream, requested_port, tunnel_handle)
        };
        let (association, relay_addr) = match association {
            Ok(association) => association,
            Err(error) => {
                self.sockets.remove(tunnel_handle);
                eprintln!("[flow {id}] create UDP relay failed: {error:#}");
                self.queue_error(id, ProxyError::GeneralFailure);
                return;
            }
        };

        self.next_port = local_port.wrapping_add(1).max(49152);
        self.allocated_ports.insert(local_port);
        self.udp_associations.insert(id, association);
        if let Some(flow) = self.flows.get_mut(&id) {
            flow.local_port = local_port;
            flow.queue(&socks::udp_associate_reply(relay_addr));
            flow.set_state(LocalState::UdpAssociate);
        }
        if util::debug_enabled() {
            eprintln!("[flow {id}] UDP relay {relay_addr}, inner port {local_port}");
        }
    }

    fn resolve_udp_domain(&mut self, flow_id: u64, domain: String, port: u16, payload: Vec<u8>) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let now = StdInstant::now();
        self.udp_dns_cache
            .retain(|_, cached| cached.expires_at > now);
        if let Some(address) = self.udp_dns_cache.get(&domain).map(|cached| cached.address) {
            self.send_udp_datagram(flow_id, address, port, &payload);
            return;
        }

        let pending = PendingUdpDatagram {
            flow_id,
            port,
            payload,
        };
        if let Some(datagrams) = self.pending_udp_dns.get_mut(&domain) {
            datagrams.push(pending);
            return;
        }
        self.pending_udp_dns.insert(domain.clone(), vec![pending]);
        spawn_ipv4_query(
            domain,
            self.dns.clone(),
            DnsContext::Udp,
            self.dns_tx.clone(),
        );
    }

    fn send_udp_datagram(&mut self, flow_id: u64, remote: Ipv4Addr, port: u16, payload: &[u8]) {
        let Some(association) = self.udp_associations.get(&flow_id) else {
            return;
        };
        let socket = self
            .sockets
            .get_mut::<smol_udp::Socket>(association.tunnel_handle());
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(remote), port);
        if let Err(error) = socket.send_slice(payload, endpoint) {
            if util::debug_enabled() {
                eprintln!("[flow {flow_id}] drop UDP datagram to {remote}:{port}: {error}");
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
    udp_associations: &mut HashMap<u64, udp::Association>,
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
            if let Some(association) = udp_associations.remove(&id) {
                sockets.remove(association.tunnel_handle());
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
    use std::net::{Shutdown, TcpStream, UdpSocket};

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
        let mut udp_associations = HashMap::new();
        reap_dead_flows(
            &mut flows,
            &mut udp_associations,
            &mut sockets,
            &mut allocated_ports,
        );
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

    #[test]
    fn udp_associate_forwards_and_reaps_client_datagrams() {
        let mut device = IpTunnelDevice::new(1380);
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = 1;
        let timestamp = Instant::from_millis(0);
        let iface = Interface::new(iface_config, &mut device, timestamp);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let config = ProxyConfig {
            listen: listener.local_addr().unwrap(),
            protocol: ProxyProtocol::Socks5,
            inner_ip: Ipv4Addr::new(10, 8, 0, 2),
            gateway: Ipv4Addr::new(100, 100, 1, 1),
            mtu: 1380,
            xor_key: &[],
            sid: 1,
            token: 2,
            encryption: 0,
            dns: DnsResolver::parse("1.1.1.1").unwrap(),
        };
        let mut connections = Connections::new(listener, iface, &config).unwrap();

        let control_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let control_client = TcpStream::connect(control_listener.local_addr().unwrap()).unwrap();
        let (control_server, _) = control_listener.accept().unwrap();
        let mut flow = LocalFlow::new(control_server, ProxyProtocol::Socks5).unwrap();
        flow.input
            .extend_from_slice(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
        connections.flows.insert(7, flow);
        connections.process_request(7);
        connections.process_request(7);

        let flow = &connections.flows[&7];
        assert!(matches!(flow.state, LocalState::UdpAssociate));
        let reply: Vec<u8> = flow.output.iter().copied().collect();
        assert_eq!(&reply[..6], &[5, 0, 5, 0, 0, 1]);
        let relay = std::net::SocketAddr::from((
            Ipv4Addr::new(reply[6], reply[7], reply[8], reply[9]),
            u16::from_be_bytes([reply[10], reply[11]]),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&[0, 0, 0, 1, 1, 1, 1, 1, 0, 53, 9, 8, 7], relay)
            .unwrap();
        connections.service_udp_inputs();
        connections.poll(&mut device, timestamp);

        let packet = device.pop_tx_packet().expect("associated UDP packet");
        assert_eq!(packet[9], 17);
        assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 53);
        assert_eq!(&packet[28..], &[9, 8, 7]);

        connections.udp_dns_cache.insert(
            "example.com".to_string(),
            CachedDns {
                address: Ipv4Addr::new(1, 1, 1, 1),
                expires_at: StdInstant::now() + Duration::from_secs(60),
            },
        );
        connections.resolve_udp_domain(7, "Example.COM.".to_string(), 443, vec![6, 5, 4]);
        connections.poll(&mut device, timestamp);
        let packet = device.pop_tx_packet().expect("cached domain UDP packet");
        assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
        assert_eq!(u16::from_be_bytes([packet[22], packet[23]]), 443);
        assert_eq!(&packet[28..], &[6, 5, 4]);

        connections.flows.get_mut(&7).unwrap().output.clear();
        control_client.shutdown(Shutdown::Both).unwrap();
        connections.service_inputs();
        connections.reap();
        assert!(!connections.flows.contains_key(&7));
        assert!(!connections.udp_associations.contains_key(&7));
        assert!(connections.allocated_ports.is_empty());
    }
}
