use clap::Parser;

/// iWAN SD-WAN server — authenticate clients and forward their tunneled traffic.
#[derive(Parser)]
#[command(name = "iwan-server", version)]
pub struct Cli {
    #[arg(long, default_value = "6001")]
    pub port: u16,
    #[arg(long, default_value = "iwan-srv")]
    pub tun: String,
    #[arg(long, default_value = "198.18.0.1")]
    pub server_ip: String,
    #[arg(long, default_value = "198.18.0.0/16")]
    pub subnet: String,
    #[arg(long, default_value = "114.114.114.114")]
    pub dns: String,
    #[arg(long, default_value = "/etc/iwan/users.txt")]
    pub users: String,
    #[arg(long, default_value = "eth0")]
    pub nat_if: String,
}
