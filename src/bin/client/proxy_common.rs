use crate::cli::LocalProxyArgs;
use anyhow::{Context, Result};
use iwan::core::auth;
use iwan::core::dns::DnsResolver;
use iwan::core::local_proxy::{self, ProxyConfig, ProxyProtocol};
use std::net::SocketAddr;
use std::time::Duration;

pub fn run(args: &LocalProxyArgs, protocol: ProxyProtocol, listen: SocketAddr) -> Result<()> {
    let dns = DnsResolver::parse(&args.dns)
        .with_context(|| format!("invalid --dns value {:?}", args.dns))?;
    let ct = auth::get_ct(&args.user, &args.pass, args.ct_pass.as_deref())?;
    let nonce = auth::rand_u32()?;
    let open = auth::build_open(&args.user, &ct, args.mtu, args.encrypt, nonce);
    let sock = auth::udp_connect(&args.server, args.port, 3000, args.bind.as_deref())?;

    let authenticated = {
        let mut result = None;
        for i in 0u32..=3 {
            sock.send(&open).context("send OPEN")?;
            println!("[{i}] -> OPEN");
            let mut buf = [0u8; 4096];
            match sock.recv(&mut buf) {
                Ok(n) => match auth::parse_ack(&buf[..n], nonce) {
                    Ok(value) => {
                        result = Some(value);
                        break;
                    }
                    Err(e) => eprintln!("[{i}] invalid reply: {e}"),
                },
                Err(e) => eprintln!("[{i}] timeout: {e}"),
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        result.context("auth failed")?
    };

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

    local_proxy::run(
        &sock,
        ProxyConfig {
            listen,
            protocol,
            inner_ip,
            gateway,
            mtu,
            xor_key: &key[..8],
            sid: authenticated.sid,
            token: authenticated.tok,
            encryption: args.encrypt,
            dns,
        },
    )
}
