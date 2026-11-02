use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{auth, crypto, sr::SrConfig, tun, tun_proxy};
use std::time::Duration;

const AUTH_ATTEMPTS: u32 = 5;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub fn run(args: &cli::ProxyArgs) -> Result<()> {
    let route_targets = route_targets(args);
    let mut auth_failures = 0u32;

    loop {
        let sock = auth::udp_connect(&args.server, args.port, 3000, args.bind.as_deref())?;
        let ct = auth::get_ct(&args.user, &args.pass, args.ct_pass.as_deref(), &args.salt)?;
        let pipe = (args.pipeid != 0).then_some((args.pipeidx, args.pipeid));
        let srlink = args
            .sr_links
            .first()
            .copied()
            .or_else(|| (args.sr_encrypt_mode != 0).then_some(1));
        let nonce = auth::rand_u32();
        let open = auth::build_open(&args.user, &ct, args.mtu, args.encrypt, pipe, srlink, nonce);

        let auth_result = match authenticate(&sock, &open, nonce) {
            Ok(value) => value,
            Err(e) => {
                auth_failures += 1;
                eprintln!("auth failed ({auth_failures}/{AUTH_ATTEMPTS}): {e}");
                if auth_failures >= AUTH_ATTEMPTS {
                    return Err(e);
                }
                std::thread::sleep(RECONNECT_DELAY);
                continue;
            }
        };
        auth_failures = 0;

        let enc = auth_result.enc.unwrap_or(args.encrypt);
        if enc > 2 {
            anyhow::bail!("server selected unsupported encrypt mode {enc}");
        }
        println!(
            "auth OK sid={:#06x} tok={:#010x} tun={} gw={} dns={} mtu={} enc={} ipv6={:?} av={:?}",
            auth_result.sid,
            auth_result.tok,
            auth_result.tun,
            auth_result.gw,
            auth_result.dns,
            auth_result.mtu,
            enc,
            auth_result.ipv6,
            auth_result.auth_verify
        );

        let sk = crypto::session_key(&args.user, &args.pass);
        let xk: Vec<u8> = sk[..8].to_vec();
        let sr_key_mode =
            iwan::core::sr::SrKeyMode::parse(&args.sr_key_mode).context("invalid --sr-key-mode")?;
        let sr = SrConfig::from_options(
            &args.sr_password,
            &args.sr_links,
            args.sr_encrypt_mode,
            sr_key_mode,
        );

        let _ = iwan::core::util::ip_run_quiet(&["link", "del", &args.tun]);
        let tun_fd = tun::open_tun(&args.tun).context("open tun (must be root)")?;
        tun::set_nonblock(tun_fd);
        println!("tun {} fd={}", args.tun, tun_fd);

        let outcome = tun_proxy::run_pump(tun_proxy::PumpConfig {
            tun_fd,
            tun_name: &args.tun,
            sock: &sock,
            xor_key: &xk,
            aes_key: &sk,
            sid: auth_result.sid,
            token: auth_result.tok,
            encryption: enc,
            server: &args.server,
            route_targets: &route_targets,
            tun_ip: &auth_result.tun,
            tun_ipv6: auth_result.ipv6,
            mtu: auth_result.mtu,
            sr,
            duplicate: args.duplicate || auth_result.duppkt.unwrap_or(0) != 0,
        });
        tun::tun_close(tun_fd);

        match outcome {
            Ok(tun_proxy::PumpOutcome::Stopped) => {
                println!("done.");
                return Ok(());
            }
            Ok(tun_proxy::PumpOutcome::ServerClosed) => {
                eprintln!("server closed the tunnel; reconnecting...");
            }
            Err(e) => {
                eprintln!("tunnel error: {e}; reconnecting...");
            }
        }
        std::thread::sleep(RECONNECT_DELAY);
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

fn route_targets(args: &cli::ProxyArgs) -> Vec<String> {
    let mut targets = Vec::new();
    targets.extend(args.proxy_cidr.iter().cloned());
    targets.extend(args.proxy_ip.iter().cloned());
    targets.extend(args.proxy_domain.iter().cloned());
    targets
}
