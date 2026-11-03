use clap::Parser;

/// Fetch, list, or connect using iWAN server config.
///
/// Config is stored at ~/.config/iwan/servers.json with encrypted passwords intact.
#[derive(Parser)]
#[command(name = "iwan-client-oidc", version = concat!("v", env!("CARGO_PKG_VERSION")))]
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

    /// Server to connect to: name keyword or 1-based index. Skips interactive selection.
    #[arg(long)]
    pub server: Option<String>,

    /// Fetch config, print servers, choose one, and connect.
    #[arg(long)]
    pub all: bool,

    /// Ping all configured servers and connect to the lowest-latency one.
    #[arg(long)]
    pub auto: bool,

    // ── proxy options (used with --connect) ──
    /// TUN device name.
    #[cfg(target_os = "linux")]
    #[arg(long, default_value = "iwan0")]
    pub tun: String,

    /// MTU advertised during the handshake and set on the TUN device.
    #[cfg(target_os = "linux")]
    #[arg(long, default_value = "1400")]
    pub tun_mtu: u16,

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
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(0..=2))]
    pub encrypt: u8,

    /// Use a rootless userspace SOCKS5 proxy instead of a TUN device.
    #[arg(long)]
    pub socks: bool,

    /// Local SOCKS5 listen address.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub socks_listen: std::net::SocketAddr,

    /// Maximum userspace inner IP MTU for --socks or --http.
    #[arg(long, default_value = "1380", visible_alias = "socks-mtu")]
    pub proxy_mtu: u16,

    /// Use a rootless userspace HTTP proxy instead of a TUN device.
    #[arg(long)]
    pub http: bool,

    /// Local HTTP proxy listen address.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub http_listen: std::net::SocketAddr,

    /// DNS resolver for SOCKS5/HTTP domain requests: ip[:port], tls://host[:port] or https://url.
    #[arg(long, default_value = "114.114.114.114:53")]
    pub dns: String,

    /// Bind the tunnel socket to a device (eth0, en0) or local IP.
    /// Default: the active physical NIC, wired before wireless.
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
