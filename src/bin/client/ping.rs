use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{auth, crypto, protocol};
use std::time::Instant;

pub fn run(args: &cli::PingArgs) -> Result<()> {
    let sock = auth::udp_connect(&args.server, args.port, 3000, args.bind.as_deref())?;

    for seq in 0..args.count {
        let h = protocol::pkhdr(protocol::PT_PING_REQ, 0, 0xFFFF, 0xFFFF_FFFF);
        let pkt = protocol::ctrl_pkt(&h, &[]);
        let t0 = Instant::now();
        sock.send(&pkt).context("send PING")?;
        println!(
            "-> PING {} ({}B) to {}:{}",
            seq + 1,
            pkt.len(),
            args.server,
            args.port
        );

        let mut buf = [0u8; 64];
        match sock.recv(&mut buf) {
            Ok(24)
                if buf[0] == protocol::PT_PING_RSP
                    && u16::from_be_bytes([buf[2], buf[3]]) == 0xFFFF
                    && u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) == u32::MAX
                    && protocol::verify_sig(&buf[..24]) =>
            {
                println!("<- PONG  RTT={:?}", t0.elapsed());
            }
            Ok(n) => anyhow::bail!("<- {}B type=0x{:02x} {}", n, buf[0], crypto::hex(&buf[..n])),
            Err(e) => anyhow::bail!("timeout: {e}"),
        }
        if seq + 1 < args.count {
            std::thread::sleep(std::time::Duration::from_millis(args.interval_ms));
        }
    }
    Ok(())
}
