use clap::{Parser, Subcommand};

/// iWAN client — ping, authenticate, or run a SOCKS5 proxy.
#[derive(Parser)]
#[command(name = "iwan-client", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Test server connectivity (round-trip latency).
    Ping(PingArgs),
    /// Perform authentication handshake only (debug / credential check).
    Auth(AuthArgs),
    /// Open a TUN tunnel and proxy traffic through the VPN server.
    #[cfg(target_os = "linux")]
    Proxy(ProxyArgs),
    /// Run a rootless SOCKS5 proxy using a userspace TCP/IP stack.
    Socks(SocksArgs),
}

#[derive(Parser)]
pub struct PingArgs {
    #[arg(long)]
    pub server: String,
    #[arg(long, default_value = "6001")]
    pub port: u16,
}

#[derive(Parser)]
pub struct AuthArgs {
    #[arg(long)]
    pub server: String,
    #[arg(long, default_value = "6001")]
    pub port: u16,
    #[arg(long, default_value = "_rev_m_1")]
    pub user: String,
    #[arg(long, default_value = "h#wJN0#Jy^uq-C@")]
    pub pass: String,
    #[arg(long)]
    pub ct_pass: Option<String>,
    #[arg(long, default_value = "1")]
    pub encrypt: u8,
    #[arg(long, default_value = "1400")]
    pub mtu: u16,
}

#[cfg(target_os = "linux")]
#[derive(Parser)]
pub struct ProxyArgs {
    #[arg(long)]
    pub server: String,
    #[arg(long, default_value = "6001")]
    pub port: u16,
    #[arg(long, default_value = "_rev_m_1")]
    pub user: String,
    #[arg(long, default_value = "h#wJN0#Jy^uq-C@")]
    pub pass: String,
    #[arg(long)]
    pub ct_pass: Option<String>,
    #[arg(long, default_value = "1")]
    pub encrypt: u8,
    #[arg(long, default_value = "1400")]
    pub mtu: u16,
    #[arg(long, default_value = "iwan0")]
    pub tun: String,
    #[arg(long, value_delimiter = ',')]
    pub proxy_cidr: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub proxy_ip: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub proxy_domain: Vec<String>,
}

#[derive(Parser)]
pub struct SocksArgs {
    #[arg(long)]
    pub server: String,
    #[arg(long, default_value = "6001")]
    pub port: u16,
    #[arg(long, default_value = "_rev_m_1")]
    pub user: String,
    #[arg(long, default_value = "h#wJN0#Jy^uq-C@")]
    pub pass: String,
    #[arg(long)]
    pub ct_pass: Option<String>,
    #[arg(long, default_value = "1")]
    pub encrypt: u8,
    #[arg(long, default_value = "1380")]
    pub mtu: u16,
    /// Local SOCKS5 listen address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub listen: std::net::SocketAddr,
    /// DNS resolver for domain requests: ip[:port], tls://host[:port] or https://url.
    #[arg(long, default_value = "114.114.114.114:53")]
    pub dns: String,
}
