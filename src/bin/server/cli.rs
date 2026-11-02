use clap::Parser;
use std::net::{Ipv4Addr, Ipv6Addr};

/// iWAN SD-WAN server — authenticate clients and forward their tunneled traffic.
#[derive(Parser)]
#[command(name = "iwan-server", version)]
pub struct Cli {
    #[arg(long, default_value = "6001")]
    pub port: u16,
    #[arg(long, default_value = "iwan-srv")]
    pub tun: String,
    #[arg(long, default_value = "1400")]
    pub mtu: u16,
    #[arg(long, default_value = "198.18.0.1")]
    pub server_ip: Ipv4Addr,
    #[arg(long, default_value = "198.18.0.0/16")]
    pub subnet: String,
    #[arg(long, default_value = "114.114.114.114")]
    pub dns: Ipv4Addr,
    #[arg(long, default_value = "223.5.5.5")]
    pub dns2: Ipv4Addr,
    #[arg(long, default_value = "/etc/iwan/users.txt")]
    pub users: String,
    #[arg(long, default_value = "eth0")]
    pub nat_if: String,
    #[arg(long, default_value = "fd00::1")]
    pub server_ipv6: Ipv6Addr,
    #[arg(long, default_value = "fd00::53")]
    pub dns_ipv6: Ipv6Addr,
    #[arg(long, default_value = "fd00::/64")]
    pub ipv6_subnet: String,
    #[arg(long, default_value_t = 64)]
    pub ipv6_prefix: u8,
    /// Password used for SR (SEGRT) AES encryption; must match the client.
    #[arg(long, default_value = "test")]
    pub sr_password: String,
    /// SR link labels; comma-separated. Must match the client's srlinks.
    #[arg(long, value_delimiter = ',')]
    pub sr_links: Vec<u32>,
    /// SR encryption mode: 0=off, 1=AES-128, 2=AES-256.
    #[arg(long, default_value_t = 0)]
    pub sr_encrypt_mode: u8,
    /// SR key derivation: jhash (Linux) or raw (Android ingress password).
    #[arg(long, default_value = "jhash")]
    pub sr_key_mode: String,
    /// Force each downlink packet into two 0x22 fragments (client reassembles).
    #[arg(long)]
    pub fragment: bool,
    /// Android-style password salt (empty keeps Linux/Rust derivation).
    #[arg(long, default_value = "")]
    pub salt: String,
    /// T_DUPPKT value advertised to clients (0 disables duplicate TX).
    #[arg(long, default_value_t = 0)]
    pub duppkt: u8,
}
