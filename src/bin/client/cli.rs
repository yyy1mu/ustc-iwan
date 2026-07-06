use clap::{Parser, Subcommand};

/// iWAN SD-WAN client — ping, authenticate, or proxy traffic over the tunnel.
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
    Proxy(ProxyArgs),
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
