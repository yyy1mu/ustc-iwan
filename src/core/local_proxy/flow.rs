use anyhow::Result;
use smoltcp::iface::SocketHandle;
use std::collections::VecDeque;
use std::net::TcpStream;
use std::time::Instant as StdInstant;

use super::ProxyProtocol;

#[derive(Clone, Copy, Debug)]
pub(super) enum ProxyError {
    GeneralFailure,
    HostUnreachable,
    ConnectionRefused,
    GatewayTimeout,
    CommandNotSupported,
    AddressNotSupported,
    BadRequest,
}

impl ProxyError {
    fn socks_reply(self) -> u8 {
        match self {
            Self::GeneralFailure => 1,
            Self::HostUnreachable | Self::GatewayTimeout => 4,
            Self::ConnectionRefused => 5,
            Self::CommandNotSupported => 7,
            Self::AddressNotSupported | Self::BadRequest => 8,
        }
    }

    fn http_status(self) -> (u16, &'static str) {
        match self {
            Self::GatewayTimeout => (504, "Gateway Timeout"),
            Self::CommandNotSupported | Self::AddressNotSupported => (501, "Not Implemented"),
            Self::BadRequest => (400, "Bad Request"),
            _ => (502, "Bad Gateway"),
        }
    }
}

/// How an HTTP flow was requested, decided when the request head is parsed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HttpMode {
    Connect,
    Forward,
}

pub(super) enum LocalState {
    SocksGreeting,
    SocksRequest,
    HttpHead,
    Resolving,
    Connecting,
    Established,
    Closing,
}

impl LocalState {
    pub(super) fn is_handshake(&self) -> bool {
        matches!(
            self,
            Self::SocksGreeting | Self::SocksRequest | Self::HttpHead
        )
    }
}

pub(super) struct LocalFlow {
    pub(super) stream: TcpStream,
    pub(super) state: LocalState,
    pub(super) input: Vec<u8>,
    pub(super) output: VecDeque<u8>,
    pub(super) socket: Option<SocketHandle>,
    pub(super) local_port: u16,
    pub(super) local_eof: bool,
    pub(super) http_mode: Option<HttpMode>,
    pub(super) state_since: StdInstant,
}

impl LocalFlow {
    pub(super) fn new(stream: TcpStream, protocol: ProxyProtocol) -> Result<Self> {
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream,
            state: match protocol {
                ProxyProtocol::Socks5 => LocalState::SocksGreeting,
                ProxyProtocol::Http => LocalState::HttpHead,
            },
            input: Vec::new(),
            output: VecDeque::new(),
            socket: None,
            local_port: 0,
            local_eof: false,
            http_mode: None,
            state_since: StdInstant::now(),
        })
    }

    pub(super) fn queue(&mut self, bytes: &[u8]) {
        self.output.extend(bytes);
    }

    pub(super) fn set_state(&mut self, state: LocalState) {
        self.state = state;
        self.state_since = StdInstant::now();
    }
}

pub(super) fn queue_proxy_error(flow: &mut LocalFlow, protocol: ProxyProtocol, error: ProxyError) {
    match protocol {
        ProxyProtocol::Socks5 => flow.queue(&[5, error.socks_reply(), 0, 1, 0, 0, 0, 0, 0, 0]),
        ProxyProtocol::Http => {
            let (status, reason) = error.http_status();
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            flow.queue(response.as_bytes());
        }
    }
    flow.set_state(LocalState::Closing);
}
