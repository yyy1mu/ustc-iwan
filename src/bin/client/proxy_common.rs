use crate::cli::LocalProxyArgs;
use anyhow::{Context, Result};
use iwan::core::client;
use iwan::core::dns::DnsResolver;
use iwan::core::local_proxy::{self, ProxyConfig, ProxyProtocol};
use std::net::SocketAddr;
use std::time::Duration;

pub fn run(args: &LocalProxyArgs, protocol: ProxyProtocol, listen: SocketAddr) -> Result<()> {
    loop {
        let dns = DnsResolver::parse(&args.dns)
            .with_context(|| format!("invalid --dns value {:?}", args.dns))?;
        let sr_key_mode =
            iwan::core::sr::SrKeyMode::parse(&args.sr_key_mode).context("invalid --sr-key-mode")?;
        let sr = iwan::core::sr::SrConfig::from_options(
            &args.sr_password,
            &args.sr_links,
            args.sr_encrypt_mode,
            sr_key_mode,
        )
        .map(|sr| sr.with_local_id(args.sr_local_id));

        let session = match client::open(&client::SessionConfig {
            server: &args.server,
            port: args.port,
            user: &args.user,
            pass: &args.pass,
            ct_pass: args.ct_pass.as_deref(),
            salt: &args.salt,
            mtu: args.mtu,
            encrypt: args.encrypt,
            bind: args.bind.as_deref(),
            pipe: (args.pipeid != 0).then_some((args.pipeidx, args.pipeid)),
            srlink: args
                .sr_links
                .first()
                .copied()
                .or_else(|| (args.sr_encrypt_mode != 0).then_some(1)),
            sr,
        }) {
            Ok(session) => session,
            Err(e) => {
                eprintln!("auth failed: {e}; retrying...");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        let inner_ip = session
            .auth
            .tun
            .parse()
            .context("server returned invalid tunnel IPv4 address")?;
        let gateway = session
            .auth
            .gw
            .parse()
            .context("server returned invalid gateway IPv4 address")?;
        let mtu = usize::from(session.auth.mtu.min(args.mtu));

        match local_proxy::run(
            &session.sock,
            ProxyConfig {
                listen,
                protocol,
                inner_ip,
                gateway,
                mtu,
                xor_key: &session.xor_key,
                aes_key: &session.aes_key,
                sid: session.auth.sid,
                token: session.auth.tok,
                encryption: session.encryption,
                sr: session.sr,
                duplicate: args.duplicate || session.auth.duppkt.unwrap_or(0) != 0,
                dns,
            },
        ) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("{protocol} session ended: {e}; reconnecting...");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
