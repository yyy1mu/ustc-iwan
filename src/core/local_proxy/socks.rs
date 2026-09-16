use std::net::{Ipv4Addr, SocketAddr};

use super::flow::{LocalState, ProxyError, Step};

pub(super) fn greeting(input: &[u8]) -> Step {
    if input.len() < 2 {
        return Step::Wait;
    }
    let methods = input[1] as usize;
    if input.len() < 2 + methods {
        return Step::Wait;
    }
    if input[0] != 5 || !input[2..2 + methods].contains(&0) {
        return Step::Reply {
            bytes: vec![5, 0xff],
            consumed: 0,
            next: LocalState::Closing,
        };
    }
    Step::Reply {
        bytes: vec![5, 0],
        consumed: 2 + methods,
        next: LocalState::SocksRequest,
    }
}

pub(super) fn request(input: &[u8]) -> Step {
    if input.len() < 4 {
        return Step::Wait;
    }
    if input[0] != 5 || input[2] != 0 {
        return Step::Fail(ProxyError::GeneralFailure);
    }
    if !matches!(input[1], 1 | 3) {
        return Step::Fail(ProxyError::CommandNotSupported);
    }
    let address = match parse_address(input) {
        Ok(Some(address)) => address,
        Ok(None) => return Step::Wait,
        Err(error) => return Step::Fail(error),
    };
    if input[1] == 3 {
        return Step::UdpAssociate {
            client_port: address.port,
            consumed: address.consumed,
        };
    }
    let host = match address.host {
        Address::Ipv4(address) => address.to_string(),
        Address::Domain(domain) => domain,
        Address::Ipv6 => return Step::Fail(ProxyError::AddressNotSupported),
    };
    Step::Open {
        host,
        port: address.port,
        consumed: address.consumed,
        mode: None,
        rewritten: None,
    }
}

pub(super) fn udp_associate_reply(bound: SocketAddr) -> Vec<u8> {
    let mut reply = vec![5, 0, 0];
    match bound {
        SocketAddr::V4(address) => {
            reply.push(1);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            reply.push(4);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    reply
}

enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6,
}

struct ParsedAddress {
    host: Address,
    port: u16,
    consumed: usize,
}

fn parse_address(input: &[u8]) -> Result<Option<ParsedAddress>, ProxyError> {
    match input[3] {
        1 => {
            if input.len() < 10 {
                return Ok(None);
            }
            Ok(Some(ParsedAddress {
                host: Address::Ipv4(Ipv4Addr::new(input[4], input[5], input[6], input[7])),
                port: u16::from_be_bytes([input[8], input[9]]),
                consumed: 10,
            }))
        }
        3 => {
            if input.len() < 5 {
                return Ok(None);
            }
            let domain_len = input[4] as usize;
            let request_len = 5 + domain_len + 2;
            if input.len() < request_len {
                return Ok(None);
            }
            if domain_len == 0 {
                return Err(ProxyError::HostUnreachable);
            }
            let Ok(domain) = std::str::from_utf8(&input[5..5 + domain_len]) else {
                return Err(ProxyError::HostUnreachable);
            };
            Ok(Some(ParsedAddress {
                host: Address::Domain(domain.to_string()),
                port: u16::from_be_bytes([input[5 + domain_len], input[6 + domain_len]]),
                consumed: request_len,
            }))
        }
        4 => {
            if input.len() < 22 {
                return Ok(None);
            }
            Ok(Some(ParsedAddress {
                host: Address::Ipv6,
                port: u16::from_be_bytes([input[20], input[21]]),
                consumed: 22,
            }))
        }
        _ => Err(ProxyError::AddressNotSupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greeting() {
        assert!(matches!(
            greeting(&[5, 1, 0]),
            Step::Reply { consumed: 3, .. }
        ));
        assert!(matches!(
            greeting(&[5, 1, 2]),
            Step::Reply { bytes, .. } if bytes == [5, 0xff]
        ));
        assert!(matches!(greeting(&[5, 2, 0]), Step::Wait));
    }

    #[test]
    fn parses_request() {
        let ipv4 = [5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb];
        assert!(matches!(
            request(&ipv4),
            Step::Open { host, port, consumed: 10, .. } if host == "1.2.3.4" && port == 443
        ));

        let mut domain = vec![5, 1, 0, 3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&80u16.to_be_bytes());
        assert!(matches!(
            request(&domain),
            Step::Open { host, port, consumed: 18, .. } if host == "example.com" && port == 80
        ));

        assert!(matches!(
            request(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80]),
            Step::Fail(ProxyError::CommandNotSupported)
        ));
        assert!(matches!(request(&[5, 1, 0, 4]), Step::Wait));
    }

    #[test]
    fn parses_udp_associate() {
        assert!(matches!(
            request(&[5, 3, 0, 1, 0, 0, 0, 0, 0x12, 0x34]),
            Step::UdpAssociate {
                client_port: 0x1234,
                consumed: 10
            }
        ));

        let mut ipv6 = vec![5, 3, 0, 4];
        ipv6.extend_from_slice(&[0; 16]);
        ipv6.extend_from_slice(&53u16.to_be_bytes());
        assert!(matches!(
            request(&ipv6),
            Step::UdpAssociate {
                client_port: 53,
                consumed: 22
            }
        ));
    }
}
