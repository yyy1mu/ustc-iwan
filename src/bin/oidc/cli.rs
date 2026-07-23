use clap::Parser;

/// Fetch, list, or connect using iWAN server config.
///
/// Config is stored at ~/.config/iwan/servers.json with encrypted passwords intact.
#[derive(Parser)]
#[command(name = "iwan-client-oidc", version)]
pub struct Cli {
    /// Output directory for the config file.
    #[arg(long, default_value = "~/.config/iwan")]
    pub config_dir: String,

    /// Fetch config via OIDC and save it.
    #[arg(long)]
    pub fetch: bool,

    /// Print servers from the local config file.
    #[arg(long)]
    pub list: bool,

    /// Choose a server from the local config file and connect.
    #[arg(long)]
    pub connect: bool,

    /// Fetch config, print servers, choose one, and connect.
    #[arg(long)]
    pub all: bool,

    // ── proxy options (used with --connect) ──
    /// TUN device name.
    #[cfg(target_os = "linux")]
    #[arg(long, default_value = "iwan0")]
    pub tun: String,

    /// CIDR ranges to route through the tunnel. Can be repeated or comma-separated.
    #[cfg(target_os = "linux")]
    #[arg(long, value_delimiter = ',')]
    pub proxy_cidr: Vec<String>,

    /// IPv4 addresses to route through the tunnel. Can be repeated or comma-separated.
    #[cfg(target_os = "linux")]
    #[arg(long, value_delimiter = ',')]
    pub proxy_ip: Vec<String>,

    /// Domains to resolve and route through the tunnel. Can be repeated or comma-separated.
    #[cfg(target_os = "linux")]
    #[arg(long, value_delimiter = ',')]
    pub proxy_domain: Vec<String>,

    /// Encryption method: 0=None, 1=XOR, 2=AES.
    #[arg(long, default_value = "1")]
    pub encrypt: u8,

    /// Use a rootless userspace SOCKS5 proxy instead of a TUN device.
    #[cfg(target_os = "linux")]
    #[arg(long)]
    pub socks: bool,

    /// Local SOCKS5 listen address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub socks_listen: std::net::SocketAddr,

    /// Maximum userspace inner IP MTU.
    #[arg(long, default_value = "1380")]
    pub socks_mtu: u16,
}
