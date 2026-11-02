use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{client, protocol, sr::SrKeyMode};

pub fn run(args: &cli::AuthArgs) -> Result<()> {
    let sr = iwan::core::sr::SrConfig::from_options(
        &args.sr_password,
        &args.sr_links,
        args.sr_encrypt_mode,
        SrKeyMode::parse(&args.sr_key_mode).context("invalid --sr-key-mode")?,
    );
    let session = client::open(&client::SessionConfig {
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
    })?;
    println!(
        "OK sid={:#06x} tok={:#010x} tun={} gw={} dns={} mtu={} enc={} ipv6={:?} av={:?}",
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
    let close = protocol::pkhdr(
        protocol::PT_CLOSE,
        session.encryption,
        session.auth.sid,
        session.auth.tok,
    );
    let _ = session.sock.send(&protocol::ctrl_pkt(&close, &[]));
    println!("-> CLOSE");
    Ok(())
}
