use crate::cli;
use anyhow::Result;
use iwan::core::local_proxy::ProxyProtocol;

pub fn run(args: &cli::SocksArgs) -> Result<()> {
    crate::proxy_common::run(&args.proxy, ProxyProtocol::Socks5, args.listen)
}
