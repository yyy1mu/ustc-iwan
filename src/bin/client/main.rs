mod auth;
mod cli;
mod ping;
#[cfg(target_os = "linux")]
mod proxy;
mod socks;

use anyhow::Result;
use clap::Parser;
#[cfg(target_os = "linux")]
use iwan::core::auth as cauth;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Ping(args) => ping::run(&args),
        cli::Command::Auth(args) => auth::run(&args),
        #[cfg(target_os = "linux")]
        cli::Command::Proxy(args) => {
            let ct = cauth::get_ct(&args.user, &args.pass, &args.ct_pass);
            let nonce = cauth::rand_u32()?;
            let open = cauth::build_open(&args.user, &ct, args.mtu, args.encrypt, nonce);
            proxy::run(&args, nonce, open)
        }
        cli::Command::Socks(args) => socks::run(&args),
    }
}
