use std::net::Ipv4Addr;

use super::engine::Engine;
use super::flow::{queue_proxy_error, LocalState, ProxyError};

enum Greeting {
    Incomplete,
    Accept { consumed: usize },
    Reject,
}

fn parse_greeting(input: &[u8]) -> Greeting {
    if input.len() < 2 {
        return Greeting::Incomplete;
    }
    let methods = input[1] as usize;
    if input.len() < 2 + methods {
        return Greeting::Incomplete;
    }
    if input[0] != 5 || !input[2..2 + methods].contains(&0) {
        return Greeting::Reject;
    }
    Greeting::Accept {
        consumed: 2 + methods,
    }
}

enum Request {
    Incomplete,
    Open {
        host: String,
        port: u16,
        consumed: usize,
    },
    Error(ProxyError),
}

fn parse_request(input: &[u8]) -> Request {
    if input.len() < 4 {
        return Request::Incomplete;
    }
    if input[0] != 5 || input[1] != 1 {
        return Request::Error(ProxyError::CommandNotSupported);
    }
    match input[3] {
        1 => {
            if input.len() < 10 {
                return Request::Incomplete;
            }
            Request::Open {
                host: Ipv4Addr::new(input[4], input[5], input[6], input[7]).to_string(),
                port: u16::from_be_bytes([input[8], input[9]]),
                consumed: 10,
            }
        }
        3 => {
            if input.len() < 5 {
                return Request::Incomplete;
            }
            let domain_len = input[4] as usize;
            let request_len = 5 + domain_len + 2;
            if domain_len == 0 || input.len() < request_len {
                return Request::Incomplete;
            }
            let Ok(domain) = std::str::from_utf8(&input[5..5 + domain_len]) else {
                return Request::Error(ProxyError::HostUnreachable);
            };
            Request::Open {
                host: domain.to_string(),
                port: u16::from_be_bytes([input[5 + domain_len], input[6 + domain_len]]),
                consumed: request_len,
            }
        }
        _ => Request::Error(ProxyError::AddressNotSupported),
    }
}

impl Engine<'_> {
    pub(super) fn process_socks5(&mut self, id: u64) {
        let open = {
            let Some(flow) = self.flows.get_mut(&id) else {
                return;
            };
            if matches!(flow.state, LocalState::SocksGreeting) {
                match parse_greeting(&flow.input) {
                    Greeting::Incomplete => return,
                    Greeting::Reject => {
                        flow.queue(&[5, 0xff]);
                        flow.set_state(LocalState::Closing);
                        return;
                    }
                    Greeting::Accept { consumed } => {
                        flow.input.drain(..consumed);
                        flow.queue(&[5, 0]);
                        flow.set_state(LocalState::SocksRequest);
                    }
                }
            }
            if !matches!(flow.state, LocalState::SocksRequest) {
                return;
            }
            match parse_request(&flow.input) {
                Request::Incomplete => return,
                Request::Error(error) => {
                    queue_proxy_error(flow, self.protocol, error);
                    return;
                }
                Request::Open {
                    host,
                    port,
                    consumed,
                } => {
                    flow.input.drain(..consumed);
                    Some((host, port))
                }
            }
        };
        if let Some((host, port)) = open {
            self.open_remote(id, &host, port);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greeting_and_request() {
        assert!(matches!(
            parse_greeting(&[5, 1, 0]),
            Greeting::Accept { consumed: 3 }
        ));
        assert!(matches!(parse_greeting(&[5, 1, 2]), Greeting::Reject));
        assert!(matches!(parse_greeting(&[5, 2, 0]), Greeting::Incomplete));

        let ipv4 = [5, 1, 0, 1, 1, 2, 3, 4, 0x01, 0xbb];
        assert!(matches!(
            parse_request(&ipv4),
            Request::Open { host, port, consumed: 10 }
                if host == "1.2.3.4" && port == 443
        ));

        let mut domain = vec![5, 1, 0, 3, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&80u16.to_be_bytes());
        assert!(matches!(
            parse_request(&domain),
            Request::Open { host, port, consumed: 18 }
                if host == "example.com" && port == 80
        ));

        assert!(matches!(
            parse_request(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80]),
            Request::Error(ProxyError::CommandNotSupported)
        ));
        assert!(matches!(
            parse_request(&[5, 1, 0, 4]),
            Request::Error(ProxyError::AddressNotSupported)
        ));
    }
}
