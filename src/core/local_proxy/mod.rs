mod engine;
mod flow;
mod http;
mod socks;

use anyhow::{Context, Result};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};

use crate::core::dns::DnsResolver;

use engine::Engine;

/// Local protocol spoken by the userspace proxy listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyProtocol {
    Socks5,
    Http,
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Socks5 => "SOCKS5",
            Self::Http => "HTTP",
        })
    }
}

/// Run a local proxy listener backed by a smoltcp userspace TCP/IP stack.
///
/// `sock` must already be authenticated and connected to the VPN server.
pub struct ProxyConfig<'a> {
    pub listen: SocketAddr,
    pub protocol: ProxyProtocol,
    pub inner_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mtu: usize,
    pub xor_key: &'a [u8],
    pub sid: u16,
    pub token: u32,
    pub encryption: u8,
    pub dns: DnsResolver,
}

pub fn run(sock: &UdpSocket, config: ProxyConfig<'_>) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .with_context(|| format!("bind {} listener {}", config.protocol, config.listen))?;
    listener.set_nonblocking(true)?;
    sock.set_nonblocking(true)?;

    let mut engine = Engine::new(listener, &config)?;

    println!("{} listening on {}", config.protocol, config.listen);
    if crate::core::util::debug_enabled() {
        eprintln!(
            "{} network: IP {}, gateway {}, MTU {}, DNS {}",
            config.protocol, config.inner_ip, config.gateway, config.mtu, config.dns
        );
    }

    engine.run(sock)?;
    println!("{} stopped", config.protocol);
    Ok(())
}
