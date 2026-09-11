use anyhow::Result;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Instant as StdInstant;

use super::ProxyProtocol;

const LOCAL_WRITE_LIMIT: usize = 256 * 1024;
const READ_BUFFER: usize = 16 * 1024;

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

/// Outcome of parsing one handshake step. The engine applies it to the flow,
/// keeping all state mutation in one place.
pub(super) enum Step {
    /// Not enough bytes yet.
    Wait,
    /// Reply to the client and continue in the given state.
    Reply {
        bytes: Vec<u8>,
        consumed: usize,
        next: LocalState,
    },
    /// Connect to the requested target.
    Open {
        host: String,
        port: u16,
        consumed: usize,
        mode: Option<HttpMode>,
        rewritten: Option<Vec<u8>>,
    },
    /// Reject the request.
    Fail(ProxyError),
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

    /// Move bytes from the local socket into the userspace TCP socket.
    /// Returns true when the protocol handshake should run.
    pub(super) fn pump_input(&mut self, sockets: &mut SocketSet<'_>) -> bool {
        if self.local_eof {
            return false;
        }

        if let Some(handle) = self.socket {
            if matches!(self.state, LocalState::Established) && !self.input.is_empty() {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                let available = socket.send_capacity().saturating_sub(socket.send_queue());
                let count = available.min(self.input.len());
                if count > 0 {
                    let sent = socket.send_slice(&self.input[..count]).unwrap_or(0);
                    self.input.drain(..sent);
                }
                if !self.input.is_empty() {
                    return false;
                }
            }
        }

        let max_read = match self.socket {
            Some(handle) if matches!(self.state, LocalState::Established) => {
                let socket = sockets.get::<tcp::Socket>(handle);
                socket.send_capacity().saturating_sub(socket.send_queue())
            }
            Some(_) => 0,
            None if self.state.is_handshake() => READ_BUFFER,
            None => 0,
        };
        if max_read == 0 {
            return false;
        }

        let mut buf = [0u8; READ_BUFFER];
        let read_len = buf.len().min(max_read);
        match self.stream.read(&mut buf[..read_len]) {
            Ok(0) => {
                self.local_eof = true;
                if let Some(handle) = self.socket {
                    sockets.get_mut::<tcp::Socket>(handle).close();
                    self.set_state(LocalState::Closing);
                }
            }
            Ok(n) if self.socket.is_none() => {
                self.input.extend_from_slice(&buf[..n]);
                return true;
            }
            Ok(n) => {
                if let Some(handle) = self.socket {
                    let socket = sockets.get_mut::<tcp::Socket>(handle);
                    let sent = socket.send_slice(&buf[..n]).unwrap_or(0);
                    if sent < n {
                        self.input.extend_from_slice(&buf[sent..n]);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => {
                self.local_eof = true;
                if let Some(handle) = self.socket {
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    self.set_state(LocalState::Closing);
                }
            }
        }
        false
    }

    /// Move bytes from the userspace TCP socket back to the local socket.
    pub(super) fn service_outputs(&mut self, sockets: &mut SocketSet<'_>) {
        if self.output.len() < LOCAL_WRITE_LIMIT {
            if let Some(handle) = self.socket {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                while socket.can_recv() && self.output.len() < LOCAL_WRITE_LIMIT {
                    let room = LOCAL_WRITE_LIMIT - self.output.len();
                    let mut buf = vec![0; room.min(READ_BUFFER)];
                    match socket.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => self.output.extend(&buf[..n]),
                        _ => break,
                    }
                }
            }
        }

        while !self.output.is_empty() {
            let (front, _) = self.output.as_slices();
            match self.stream.write(front) {
                Ok(0) => break,
                Ok(n) => {
                    self.output.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.local_eof = true;
                    if let Some(handle) = self.socket {
                        sockets.get_mut::<tcp::Socket>(handle).abort();
                    }
                    self.output.clear();
                    self.set_state(LocalState::Closing);
                    break;
                }
            }
        }

        if let Some(handle) = self.socket {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if remote_eof_ready(socket, self.output.is_empty()) {
                let _ = self.stream.shutdown(Shutdown::Write);
                socket.close();
                self.set_state(LocalState::Closing);
            }
        }
    }
}

fn remote_eof_ready(socket: &tcp::Socket<'_>, local_output_empty: bool) -> bool {
    socket.state() == tcp::State::CloseWait && !socket.can_recv() && local_output_empty
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
