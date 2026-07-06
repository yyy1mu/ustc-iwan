use crate::cli;
use anyhow::{Context, Result};
use iwan::core::auth;
use std::time::Duration;

pub fn run(args: &cli::AuthArgs) -> Result<()> {
    let ct = auth::get_ct(&args.user, &args.pass, &args.ct_pass);
    let nonce = auth::rand_u32()?;
    let open = auth::build_open(&args.user, &ct, args.mtu, args.encrypt, nonce);
    let sock = auth::udp_connect(&args.server, args.port, 3000)?;

    for i in 0u32..=3 {
        sock.send(&open).context("send OPEN")?;
        println!("[{i}] -> OPEN ({}B) nonce={:08x}", open.len(), nonce);
        let mut buf = [0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(m) => match auth::parse_ack(&buf[..m], nonce) {
                Ok(a) => {
                    println!(
                        "OK sid={:#06x} tok={:#010x} tun={} gw={} dns={} mtu={}",
                        a.sid, a.tok, a.tun, a.gw, a.dns, a.mtu
                    );
                    let c = iwan::core::protocol::pkhdr(
                        iwan::core::protocol::PT_CLOSE,
                        args.encrypt,
                        a.sid,
                        a.tok,
                    );
                    let _ = sock.send(&iwan::core::protocol::ctrl_pkt(&c, &[]));
                    println!("-> CLOSE");
                    return Ok(());
                }
                Err(e) => eprintln!("  err: {e}"),
            },
            Err(e) => eprintln!("  timeout: {e}"),
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    anyhow::bail!("auth failed");
}
