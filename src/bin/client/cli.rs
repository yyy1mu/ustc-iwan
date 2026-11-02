use clap::{Parser, Subcommand};

/// iWAN client — ping, authenticate, or run a SOCKS5/HTTP proxy.
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
    /// Run a rootless HTTP proxy using a userspace TCP/IP stack.
    Http(HttpArgs),
}

#[derive(Parser)]
pub struct PingArgs {
    #[arg(long)]
    pub server: String,
    #[arg(long, default_value = "6001")]
    pub port: u16,
    /// Number of PING requests to send.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..))]
    pub count: u16,
    /// Delay between requests, in milliseconds.
    #[arg(long, default_value_t = 1000)]
    pub interval_ms: u64,
    /// Bind to a device (eth0, en0) or local IP. Default: active physical NIC.
    #[arg(long)]
    pub bind: Option<String>,
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
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(0..=2))]
    pub encrypt: u8,
    #[arg(long, default_value = "1400")]
    pub mtu: u16,
    /// Bind to a device (eth0, en0) or local IP. Default: active physical NIC.
    #[arg(long)]
    pub bind: Option<String>,
    /// Pipe ID for server-side multi-path selection (0 = disabled).
    #[arg(long, default_value_t = 0)]
    pub pipeid: u16,
    /// Pipe direction/bit (0 or 1), only used when pipeid != 0.
    #[arg(long, default_value_t = 0)]
    pub pipeidx: u16,
    /// SR link labels; comma-separated. Must match the server.
    #[arg(long, value_delimiter = ',')]
    pub sr_links: Vec<u32>,
    /// SR password; used only when sr_encrypt_mode != 0.
    #[arg(long, default_value = "test")]
    pub sr_password: String,
    /// SR encryption mode: 0=off, 1=AES-128, 2=AES-256.
    #[arg(long, default_value_t = 0)]
    pub sr_encrypt_mode: u8,
    /// SR key derivation: jhash (Linux) or raw (Android ingress password).
    #[arg(long, default_value = "jhash")]
    pub sr_key_mode: String,
    /// Android-style password salt (empty keeps Linux/Rust derivation).
    #[arg(long, default_value = "")]
    pub salt: String,
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
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(0..=2))]
    pub encrypt: u8,
    #[arg(long, default_value = "1400")]
    pub mtu: u16,
    /// Bind to a device (eth0, en0) or local IP. Default: active physical NIC.
    #[arg(long)]
    pub bind: Option<String>,
    #[arg(long, default_value = "iwan0")]
    pub tun: String,
    #[arg(long, value_delimiter = ',')]
    pub proxy_cidr: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub proxy_ip: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    pub proxy_domain: Vec<String>,
    /// Pipe ID for server-side multi-path selection (0 = disabled).
    #[arg(long, default_value_t = 0)]
    pub pipeid: u16,
    /// Pipe direction/bit (0 or 1), only used when pipeid != 0.
    #[arg(long, default_value_t = 0)]
    pub pipeidx: u16,
    /// SR link labels; comma-separated. Must match the server.
    #[arg(long, value_delimiter = ',')]
    pub sr_links: Vec<u32>,
    /// SR password; used only when sr_encrypt_mode != 0.
    #[arg(long, default_value = "test")]
    pub sr_password: String,
    /// SR encryption mode: 0=off, 1=AES-128, 2=AES-256.
    #[arg(long, default_value_t = 0)]
    pub sr_encrypt_mode: u8,
    /// SR key derivation: jhash (Linux) or raw (Android ingress password).
    #[arg(long, default_value = "jhash")]
    pub sr_key_mode: String,
    /// Android-style password salt (empty keeps Linux/Rust derivation).
    #[arg(long, default_value = "")]
    pub salt: String,
    /// Local SR ID included in SrmonPkt.
    #[arg(long, default_value_t = 0)]
    pub sr_local_id: u32,
    /// Send each data packet twice using DATA_DUP/DATA_ENC_DUP.
    #[arg(long)]
    pub duplicate: bool,
}

#[derive(Parser)]
pub struct LocalProxyArgs {
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
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(0..=2))]
    pub encrypt: u8,
    #[arg(long, default_value = "1380")]
    pub mtu: u16,
    /// DNS resolver for domain requests: ip[:port], tls://host[:port] or https://url.
    #[arg(long, default_value = "114.114.114.114:53")]
    pub dns: String,
    /// Bind to a device (eth0, en0) or local IP. Default: active physical NIC.
    #[arg(long)]
    pub bind: Option<String>,
    /// Pipe ID for server-side multi-path selection (0 = disabled).
    #[arg(long, default_value_t = 0)]
    pub pipeid: u16,
    /// Pipe direction/bit (0 or 1), only used when pipeid != 0.
    #[arg(long, default_value_t = 0)]
    pub pipeidx: u16,
    /// SR link labels; comma-separated. Must match the server.
    #[arg(long, value_delimiter = ',')]
    pub sr_links: Vec<u32>,
    /// SR password; used only when sr_encrypt_mode != 0.
    #[arg(long, default_value = "test")]
    pub sr_password: String,
    /// SR encryption mode: 0=off, 1=AES-128, 2=AES-256.
    #[arg(long, default_value_t = 0)]
    pub sr_encrypt_mode: u8,
    /// SR key derivation: jhash (Linux) or raw (Android ingress password).
    #[arg(long, default_value = "jhash")]
    pub sr_key_mode: String,
    /// Android-style password salt (empty keeps Linux/Rust derivation).
    #[arg(long, default_value = "")]
    pub salt: String,
    /// Local SR ID included in SrmonPkt.
    #[arg(long, default_value_t = 0)]
    pub sr_local_id: u32,
    /// Send each data packet twice using DATA_DUP/DATA_ENC_DUP.
    #[arg(long)]
    pub duplicate: bool,
}

#[derive(Parser)]
pub struct SocksArgs {
    #[command(flatten)]
    pub proxy: LocalProxyArgs,
    /// Local SOCKS5 listen address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub listen: std::net::SocketAddr,
}

#[derive(Parser)]
pub struct HttpArgs {
    #[command(flatten)]
    pub proxy: LocalProxyArgs,
    /// Local HTTP proxy listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub listen: std::net::SocketAddr,
}
