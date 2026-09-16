use anyhow::{Context, Result};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::core::dns::{build_a_query, parse_a_response, DnsResult, DNS_TIMEOUT};

const LOCAL_PORT: u16 = 5300;
const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const PACKET_SLOTS: usize = 32;
const MESSAGE_LIMIT: usize = 4096;

pub(super) struct TunnelDns<T> {
    server: SocketAddrV4,
    socket: SocketHandle,
    queries: HashMap<u16, PendingQuery<T>>,
}

struct PendingQuery<T> {
    domain: String,
    packet: Vec<u8>,
    context: T,
    retry_at: Instant,
    deadline: Instant,
}

impl<T> TunnelDns<T> {
    pub(super) fn new(server: SocketAddrV4, sockets: &mut SocketSet<'_>) -> Result<Self> {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
            vec![0; MESSAGE_LIMIT * PACKET_SLOTS],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
            vec![0; MESSAGE_LIMIT * PACKET_SLOTS],
        );
        let mut socket = udp::Socket::new(rx, tx);
        socket
            .bind(LOCAL_PORT)
            .context("bind tunneled DNS socket")?;
        Ok(Self {
            server,
            socket: sockets.add(socket),
            queries: HashMap::new(),
        })
    }

    pub(super) fn start(
        &mut self,
        domain: String,
        context: T,
        sockets: &mut SocketSet<'_>,
    ) -> std::result::Result<(), (T, anyhow::Error)> {
        let Some(id) = self.allocate_id() else {
            return Err((
                context,
                anyhow::anyhow!("DNS transaction ID space exhausted"),
            ));
        };
        let packet = match build_a_query(id, &domain) {
            Ok(packet) => packet,
            Err(error) => return Err((context, error)),
        };
        if let Err(error) = sockets
            .get_mut::<udp::Socket>(self.socket)
            .send_slice(&packet, self.server_endpoint())
        {
            return Err((context, anyhow::anyhow!(error)));
        }
        let now = Instant::now();
        self.queries.insert(
            id,
            PendingQuery {
                domain,
                packet,
                context,
                retry_at: now + RETRY_INTERVAL,
                deadline: now + DNS_TIMEOUT,
            },
        );
        Ok(())
    }

    pub(super) fn service(&mut self, sockets: &mut SocketSet<'_>) -> Vec<DnsResult<T>> {
        let server = self.server_endpoint();
        let mut responses = Vec::new();
        let socket = sockets.get_mut::<udp::Socket>(self.socket);
        while let Ok((packet, metadata)) = socket.recv() {
            if metadata.endpoint == server && packet.len() >= 2 {
                responses.push(packet.to_vec());
            }
        }

        let mut completed = Vec::new();
        for packet in responses {
            let id = u16::from_be_bytes([packet[0], packet[1]]);
            if self.queries.contains_key(&id) {
                let result = parse_a_response(id, &packet).map_err(|_| ());
                if let Some(result) = self.finish(id, result) {
                    completed.push(result);
                }
            }
        }

        let now = Instant::now();
        let ids: Vec<u16> = self.queries.keys().copied().collect();
        for id in ids {
            let Some(query) = self.queries.get(&id) else {
                continue;
            };
            if now >= query.deadline {
                if let Some(result) = self.finish(id, Err(())) {
                    completed.push(result);
                }
            } else if now >= query.retry_at {
                let packet = query.packet.clone();
                if sockets
                    .get_mut::<udp::Socket>(self.socket)
                    .send_slice(&packet, server)
                    .is_ok()
                {
                    if let Some(query) = self.queries.get_mut(&id) {
                        query.retry_at = now + RETRY_INTERVAL;
                    }
                }
            }
        }
        completed
    }

    pub(super) fn close(&mut self, sockets: &mut SocketSet<'_>) {
        sockets.get_mut::<udp::Socket>(self.socket).close();
    }

    fn finish(
        &mut self,
        id: u16,
        result: std::result::Result<crate::core::dns::DnsAnswer, ()>,
    ) -> Option<DnsResult<T>> {
        let query = self.queries.remove(&id)?;
        Some(DnsResult {
            context: query.context,
            domain: query.domain,
            result,
        })
    }

    fn allocate_id(&self) -> Option<u16> {
        let start = rand::random::<u16>();
        (0..=u16::MAX)
            .map(|offset| start.wrapping_add(offset))
            .find(|id| !self.queries.contains_key(id))
    }

    fn server_endpoint(&self) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv4(*self.server.ip()), self.server.port())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::netstack::IpTunnelDevice;
    use smoltcp::iface::{Config, Interface};
    use smoltcp::time::Instant as SmolInstant;
    use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Packet, UdpPacket};
    use std::net::Ipv4Addr;

    #[test]
    fn resolves_over_the_tunnel_data_plane() {
        let mut device = IpTunnelDevice::new(1380);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 1;
        let timestamp = SmolInstant::from_millis(0);
        let mut iface = Interface::new(config, &mut device, timestamp);
        let local_ip = Ipv4Addr::new(10, 8, 0, 2);
        let server_ip = Ipv4Addr::new(202, 38, 64, 1);
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv4(local_ip), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(100, 100, 1, 1))
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let mut dns = TunnelDns::new(SocketAddrV4::new(server_ip, 53), &mut sockets).unwrap();
        dns.start("example.com".to_string(), 7u64, &mut sockets)
            .unwrap();

        iface.poll(timestamp, &mut device, &mut sockets);
        let mut response = device.pop_tx_packet().expect("DNS UDP query");
        assert_eq!(response[9], 17);
        assert_eq!(&response[16..20], &server_ip.octets());
        assert_eq!(u16::from_be_bytes([response[20], response[21]]), LOCAL_PORT);

        response[12..16].copy_from_slice(&server_ip.octets());
        response[16..20].copy_from_slice(&local_ip.octets());
        response[20..22].copy_from_slice(&53u16.to_be_bytes());
        response[22..24].copy_from_slice(&LOCAL_PORT.to_be_bytes());
        response[30..32].copy_from_slice(&0x8180u16.to_be_bytes());
        response[34..36].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let packet_len = response.len() as u16;
        response[2..4].copy_from_slice(&packet_len.to_be_bytes());
        response[10..12].fill(0);
        let udp_len = packet_len - 20;
        response[24..26].copy_from_slice(&udp_len.to_be_bytes());
        response[26..28].fill(0);
        Ipv4Packet::new_unchecked(&mut response).fill_checksum();
        UdpPacket::new_unchecked(&mut response[20..])
            .fill_checksum(&IpAddress::Ipv4(server_ip), &IpAddress::Ipv4(local_ip));
        device.push_rx_packet(response);
        iface.poll(timestamp, &mut device, &mut sockets);
        let results = dns.service(&mut sockets);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].context, 7);
        assert_eq!(results[0].domain, "example.com");
        assert_eq!(
            results[0].result.as_ref().unwrap().address,
            Ipv4Addr::new(1, 2, 3, 4)
        );
    }
}
