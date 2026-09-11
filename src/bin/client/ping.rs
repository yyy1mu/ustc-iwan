use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{auth, crypto, protocol};
use std::time::Instant;

pub fn run(args: &cli::PingArgs) -> Result<()> {
    let sock = auth::udp_connect(&args.server, args.port, 3000, args.bind.as_deref())?;

    let h = protocol::pkhdr(protocol::PT_PING_REQ, 0, 0xFFFF, 0xFFFF_FFFF);
    let pkt = protocol::ctrl_pkt(&h, &[]);
    sock.send(&pkt).context("send PING")?;
    println!("-> PING ({}B) to {}:{}", pkt.len(), args.server, args.port);

    let mut buf = [0u8; 64];
    let t0 = Instant::now();
    match sock.recv(&mut buf) {
        Ok(24) if buf[0] == protocol::PT_PING_RSP && protocol::verify_sig(&buf[..24]) => {
            println!("<- PONG  RTT={:?}", t0.elapsed());
            Ok(())
        }
        Ok(n) => anyhow::bail!("<- {}B type=0x{:02x} {}", n, buf[0], crypto::hex(&buf[..n])),
        Err(e) => anyhow::bail!("timeout: {e}"),
    }
}
