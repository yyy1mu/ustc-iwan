use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{crypto, protocol};
use std::time::Instant;

pub fn run(args: &cli::PingArgs) -> Result<()> {
    let addr: std::net::SocketAddr = format!("{}:{}", args.server, args.port)
        .parse()
        .context("invalid server address")?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").context("bind UDP")?;
    sock.connect(addr).context("connect UDP")?;
    sock.set_read_timeout(Some(std::time::Duration::from_millis(3000)))
        .ok();

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
