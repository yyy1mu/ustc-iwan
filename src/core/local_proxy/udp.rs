use anyhow::{Context, Result};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::wire::{IpAddress, IpEndpoint};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};

const PACKET_SLOTS: usize = 64;
const LOCAL_DATAGRAM_BUFFER_SIZE: usize = u16::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Target {
    Ipv4(Ipv4Addr, u16),
    Domain(String, u16),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Datagram {
    pub(super) target: Target,
    pub(super) payload: Vec<u8>,
}

pub(super) struct Association {
    relay: UdpSocket,
    tunnel_handle: SocketHandle,
    control_peer: SocketAddr,
    client_addr: Option<SocketAddr>,
    receive_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
}

impl Association {
    pub(super) fn bind(
        control: &TcpStream,
        requested_port: u16,
        tunnel_handle: SocketHandle,
    ) -> Result<(Self, SocketAddr)> {
        let control_local = control.local_addr().context("read SOCKS control address")?;
        let control_peer = control.peer_addr().context("read SOCKS client address")?;
        let relay = UdpSocket::bind(SocketAddr::new(control_local.ip(), 0))
            .context("bind SOCKS5 UDP relay")?;
        relay.set_nonblocking(true)?;
        let relay_addr = relay.local_addr()?;
        let client_addr =
            (requested_port != 0).then(|| SocketAddr::new(control_peer.ip(), requested_port));
        Ok((
            Self {
                relay,
                tunnel_handle,
                control_peer,
                client_addr,
                receive_buffer: vec![0; LOCAL_DATAGRAM_BUFFER_SIZE],
                response_buffer: Vec::with_capacity(LOCAL_DATAGRAM_BUFFER_SIZE),
            },
            relay_addr,
        ))
    }

    pub(super) fn tunnel_handle(&self) -> SocketHandle {
        self.tunnel_handle
    }

    pub(super) fn receive(&mut self, max_payload: usize) -> Result<Option<Datagram>> {
        loop {
            let (length, source) = match self.relay.recv_from(&mut self.receive_buffer) {
                Ok(packet) => packet,
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error).context("receive SOCKS5 UDP datagram"),
            };
            if source.ip() != self.control_peer.ip() {
                continue;
            }
            if let Some(client_addr) = self.client_addr {
                if source != client_addr {
                    continue;
                }
            } else {
                self.client_addr = Some(source);
            }
            if let Some(datagram) = parse_datagram(&self.receive_buffer[..length], max_payload) {
                return Ok(Some(datagram));
            }
        }
    }

    pub(super) fn send_response(&mut self, remote: IpEndpoint, payload: &[u8]) -> Result<()> {
        let Some(client_addr) = self.client_addr else {
            return Ok(());
        };
        encode_response(&mut self.response_buffer, remote, payload);
        match self.relay.send_to(&self.response_buffer, client_addr) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error).context("send SOCKS5 UDP response"),
        }
    }
}

pub(super) fn new_tunnel_socket(
    local_port: u16,
    max_payload: usize,
) -> Result<udp::Socket<'static>> {
    let payload_capacity = max_payload.saturating_mul(PACKET_SLOTS);
    let rx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
        vec![0; payload_capacity],
    );
    let tx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; PACKET_SLOTS],
        vec![0; payload_capacity],
    );
    let mut socket = udp::Socket::new(rx, tx);
    socket
        .bind(local_port)
        .context("bind tunneled UDP socket")?;
    Ok(socket)
}

fn parse_datagram(packet: &[u8], max_payload: usize) -> Option<Datagram> {
    if packet.len() < 4 || packet[..2] != [0, 0] || packet[2] != 0 {
        return None;
    }
    let (target, payload_offset) = match packet[3] {
        1 => {
            if packet.len() < 10 {
                return None;
            }
            let address = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            if address.is_unspecified() || port == 0 {
                return None;
            }
            (Target::Ipv4(address, port), 10)
        }
        3 => {
            let length = *packet.get(4)? as usize;
            let payload_offset = 5usize.checked_add(length)?.checked_add(2)?;
            if length == 0 || packet.len() < payload_offset {
                return None;
            }
            let domain = std::str::from_utf8(&packet[5..5 + length]).ok()?;
            let port = u16::from_be_bytes([packet[5 + length], packet[6 + length]]);
            if port == 0 {
                return None;
            }
            (Target::Domain(domain.to_string(), port), payload_offset)
        }
        _ => return None,
    };
    let payload = packet.get(payload_offset..)?;
    if payload.len() > max_payload {
        return None;
    }
    Some(Datagram {
        target,
        payload: payload.to_vec(),
    })
}

fn encode_response(packet: &mut Vec<u8>, remote: IpEndpoint, payload: &[u8]) {
    let IpAddress::Ipv4(address) = remote.addr;
    packet.clear();
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&address.octets());
    packet.extend_from_slice(&remote.port.to_be_bytes());
    packet.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::SocketSet;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn parses_ipv4_and_domain_datagrams() {
        let ipv4 = [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 9, 8, 7];
        assert_eq!(
            parse_datagram(&ipv4, 100),
            Some(Datagram {
                target: Target::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 53),
                payload: vec![9, 8, 7],
            })
        );

        let mut domain = vec![0, 0, 0, 3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        domain.extend_from_slice(&[1, 2]);
        assert_eq!(
            parse_datagram(&domain, 100),
            Some(Datagram {
                target: Target::Domain("example.com".to_string(), 443),
                payload: vec![1, 2],
            })
        );
    }

    #[test]
    fn rejects_fragmented_and_oversized_datagrams() {
        let fragmented = [0, 0, 1, 1, 1, 2, 3, 4, 0, 53, 9];
        assert_eq!(parse_datagram(&fragmented, 100), None);

        let oversized = [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 9, 8];
        assert_eq!(parse_datagram(&oversized, 1), None);
    }

    #[test]
    fn relays_datagrams_for_the_control_connection_client() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _control_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (control_server, _) = listener.accept().unwrap();

        let mut sockets = SocketSet::new(vec![]);
        let tunnel_handle = sockets.add(new_tunnel_socket(49152, 1352).unwrap());
        let (mut association, relay_addr) =
            Association::bind(&control_server, 0, tunnel_handle).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let request = [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 9, 8];
        client.send_to(&request, relay_addr).unwrap();
        assert_eq!(
            association.receive(1352).unwrap(),
            Some(Datagram {
                target: Target::Ipv4(Ipv4Addr::new(1, 2, 3, 4), 53),
                payload: vec![9, 8],
            })
        );

        association
            .send_response(
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53),
                &[7, 6],
            )
            .unwrap();
        let mut response = [0u8; 32];
        let (length, source) = client.recv_from(&mut response).unwrap();
        assert_eq!(source, relay_addr);
        assert_eq!(&response[..length], &[0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 7, 6]);
    }
}
