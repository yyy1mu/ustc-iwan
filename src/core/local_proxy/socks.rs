use std::net::Ipv4Addr;

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
    if input[0] != 5 || input[1] != 1 {
        return Step::Fail(ProxyError::CommandNotSupported);
    }
    match input[3] {
        1 => {
            if input.len() < 10 {
                return Step::Wait;
            }
            Step::Open {
                host: Ipv4Addr::new(input[4], input[5], input[6], input[7]).to_string(),
                port: u16::from_be_bytes([input[8], input[9]]),
                consumed: 10,
                mode: None,
                rewritten: None,
            }
        }
        3 => {
            if input.len() < 5 {
                return Step::Wait;
            }
            let domain_len = input[4] as usize;
            let request_len = 5 + domain_len + 2;
            if domain_len == 0 || input.len() < request_len {
                return Step::Wait;
            }
            let Ok(domain) = std::str::from_utf8(&input[5..5 + domain_len]) else {
                return Step::Fail(ProxyError::HostUnreachable);
            };
            Step::Open {
                host: domain.to_string(),
                port: u16::from_be_bytes([input[5 + domain_len], input[6 + domain_len]]),
                consumed: request_len,
                mode: None,
                rewritten: None,
            }
        }
        _ => Step::Fail(ProxyError::AddressNotSupported),
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
        assert!(matches!(
            request(&[5, 1, 0, 4]),
            Step::Fail(ProxyError::AddressNotSupported)
        ));
    }
}
