use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{client, sr::SrConfig, tun, tun_proxy};
use std::time::Duration;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub fn run(args: &cli::ProxyArgs) -> Result<()> {
    let route_targets = route_targets(args);

    loop {
        let sr_key_mode =
            iwan::core::sr::SrKeyMode::parse(&args.sr_key_mode).context("invalid --sr-key-mode")?;
        let sr = SrConfig::from_options(
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
                std::thread::sleep(RECONNECT_DELAY);
                continue;
            }
        };

        println!(
            "auth OK sid={:#06x} tok={:#010x} tun={} gw={} dns={} mtu={} enc={} ipv6={:?} av={:?}",
            session.auth.sid,
            session.auth.tok,
            session.auth.tun,
            session.auth.gw,
            session.auth.dns,
            session.auth.mtu,
            session.encryption,
            session.auth.ipv6,
            session.auth.auth_verify
        );

        let _ = iwan::core::util::ip_run_quiet(&["link", "del", &args.tun]);
        let tun_fd = tun::open_tun(&args.tun).context("open tun (must be root)")?;
        tun::set_nonblock(tun_fd);
        println!("tun {} fd={}", args.tun, tun_fd);

        let outcome = tun_proxy::run_pump(tun_proxy::PumpConfig {
            tun_fd,
            tun_name: &args.tun,
            sock: &session.sock,
            xor_key: &session.xor_key,
            aes_key: &session.aes_key,
            sid: session.auth.sid,
            token: session.auth.tok,
            encryption: session.encryption,
            server: &args.server,
            route_targets: &route_targets,
            tun_ip: &session.auth.tun,
            tun_ipv6: session.auth.ipv6,
            mtu: session.auth.mtu,
            sr: session.sr,
            duplicate: args.duplicate || session.auth.duppkt.unwrap_or(0) != 0,
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

fn route_targets(args: &cli::ProxyArgs) -> Vec<String> {
    let mut targets = Vec::new();
    targets.extend(args.proxy_cidr.iter().cloned());
    targets.extend(args.proxy_ip.iter().cloned());
    targets.extend(args.proxy_domain.iter().cloned());
    targets
}
