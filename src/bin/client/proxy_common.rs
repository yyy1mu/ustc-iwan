use crate::cli::LocalProxyArgs;
use anyhow::{Context, Result};
use iwan::core::auth;
use iwan::core::dns::DnsResolver;
use iwan::core::local_proxy::{self, ProxyConfig, ProxyProtocol};
use std::net::SocketAddr;
use std::time::Duration;

const AUTH_ATTEMPTS: u32 = 5;

pub fn run(args: &LocalProxyArgs, protocol: ProxyProtocol, listen: SocketAddr) -> Result<()> {
    let mut failures = 0u32;
    loop {
        let dns = DnsResolver::parse(&args.dns)
            .with_context(|| format!("invalid --dns value {:?}", args.dns))?;
        let ct = auth::get_ct(&args.user, &args.pass, args.ct_pass.as_deref(), &args.salt)?;
        let pipe = (args.pipeid != 0).then_some((args.pipeidx, args.pipeid));
        let srlink = args
            .sr_links
            .first()
            .copied()
            .or_else(|| (args.sr_encrypt_mode != 0).then_some(1));
        let nonce = auth::rand_u32();
        let open = auth::build_open(&args.user, &ct, args.mtu, args.encrypt, pipe, srlink, nonce);
        let sock = auth::udp_connect(&args.server, args.port, 3000, args.bind.as_deref())?;

        let authenticated = match authenticate(&sock, &open, nonce) {
            Ok(value) => value,
            Err(e) => {
                failures += 1;
                eprintln!("auth failed ({failures}/{AUTH_ATTEMPTS}): {e}");
                if failures >= AUTH_ATTEMPTS {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        failures = 0;

        let inner_ip = authenticated
            .tun
            .parse()
            .context("server returned invalid tunnel IPv4 address")?;
        let gateway = authenticated
            .gw
            .parse()
            .context("server returned invalid gateway IPv4 address")?;
        let key = iwan::core::crypto::session_key(&args.user, &args.pass);
        let mtu = usize::from(authenticated.mtu.min(args.mtu));
        let enc = authenticated.enc.unwrap_or(args.encrypt);
        let sr_key_mode =
            iwan::core::sr::SrKeyMode::parse(&args.sr_key_mode).context("invalid --sr-key-mode")?;
        let sr = iwan::core::sr::SrConfig::from_options(
            &args.sr_password,
            &args.sr_links,
            args.sr_encrypt_mode,
            sr_key_mode,
        );

        match local_proxy::run(
            &sock,
            ProxyConfig {
                listen,
                protocol,
                inner_ip,
                gateway,
                mtu,
                xor_key: &key[..8],
                aes_key: &key,
                sid: authenticated.sid,
                token: authenticated.tok,
                encryption: enc,
                sr,
                duplicate: args.duplicate || authenticated.duppkt.unwrap_or(0) != 0,
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

fn authenticate(sock: &std::net::UdpSocket, open: &[u8], nonce: u32) -> Result<auth::AuthResult> {
    let mut last_error = None;
    for i in 0u32..=3 {
        sock.send(open).context("send OPEN")?;
        println!("[{i}] -> OPEN");
        let mut buf = [0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(n) => match auth::parse_ack(&buf[..n], nonce) {
                Ok(value) => return Ok(value),
                Err(e) => last_error = Some(e),
            },
            Err(e) => last_error = Some(anyhow::anyhow!("timeout: {e}")),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("auth failed")))
}
