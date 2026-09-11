mod cli;
mod config;
mod connect;
mod controller;
mod oidc;

use anyhow::Result;
use clap::Parser;

const DOMAIN: &str = "iwan.ustc";
const APP_SECRET: &str = "ca6a3532abd2986a03b86b3a";

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    if !(cli.fetch || cli.list || cli.connect || cli.all) {
        anyhow::bail!("choose one action: --fetch, --list, --connect, or --all");
    }

    let path = config::resolve_dir(&cli.config_dir).join("servers.json");
    let do_fetch = cli.fetch || cli.all;
    let do_list = cli.list || cli.all;
    let do_connect = cli.connect || cli.all;
    if cli.socks && cli.http {
        anyhow::bail!("--socks and --http are mutually exclusive");
    }
    if (cli.socks || cli.http) && !do_connect {
        anyhow::bail!("--socks or --http requires --connect or --all");
    }
    #[cfg(not(target_os = "linux"))]
    if do_connect && !(cli.socks || cli.http) {
        anyhow::bail!("--socks or --http is required for --connect or --all on this platform");
    }

    let config = if do_fetch {
        let config = connect::fetch_config()?;
        config::save_config(&path, &config)?;
        config
    } else {
        config::load_config(&path)?
    };

    if do_list || do_connect {
        connect::print_servers(&config.servers);
    }
    if do_connect {
        connect::connect_server(&cli, &config)?;
    }

    Ok(())
}
