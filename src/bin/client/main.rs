mod auth;
mod cli;
mod http;
mod ping;
#[cfg(target_os = "linux")]
mod proxy;
mod proxy_common;
mod socks;

use anyhow::Result;
use clap::Parser;
fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Ping(args) => ping::run(&args),
        cli::Command::Auth(args) => auth::run(&args),
        #[cfg(target_os = "linux")]
        cli::Command::Proxy(args) => proxy::run(&args),
        cli::Command::Socks(args) => socks::run(&args),
        cli::Command::Http(args) => http::run(&args),
    }
}
