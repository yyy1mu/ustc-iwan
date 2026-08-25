use crate::cli;
use anyhow::{Context, Result};
use iwan::core::{auth, crypto, proxy, tun};
use std::net::UdpSocket;
use std::time::Duration;
use std::os::fd::AsRawFd;

pub fn run(args: &cli::ProxyArgs, nonce: u32, open: Vec<u8>) -> Result<()> {
    let addr: std::net::SocketAddr = format!("{}:{}", args.server, args.port)
        .parse()
        .context("invalid address")?;
    let sock = UdpSocket::bind("0.0.0.0:0").context("bind UDP")?;
    sock.connect(addr).context("connect UDP")?;

    // Larger UDP buffers
    {
        const BUFSZ: libc::c_int = 16 * 1024 * 1024;
        let fd = sock.as_raw_fd();
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &BUFSZ as *const _ as *const libc::c_void,
                std::mem::size_of_val(&BUFSZ) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &BUFSZ as *const _ as *const libc::c_void,
                std::mem::size_of_val(&BUFSZ) as libc::socklen_t,
            );
        }
    }
    sock.set_read_timeout(Some(Duration::from_millis(3000)))
        .ok();

    let auth = {
        let mut result = None;
        for i in 0u32..=3 {
            sock.send(&open).context("send OPEN")?;
            println!("[{i}] -> OPEN");
            let mut buf = [0u8; 4096];
            match sock.recv(&mut buf) {
                Ok(m) => match auth::parse_ack(&buf[..m], nonce) {
                    Ok(aa) => {
                        result = Some(aa);
                        break;
                    }
                    Err(e) => eprintln!("  [{i}] err: {e}"),
                },
                Err(e) => eprintln!("  [{i}] timeout: {e}"),
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        result.context("auth failed")?
    };

    println!(
        "auth OK sid={:#06x} tok={:#010x} tun={} gw={} dns={} mtu={}",
        auth.sid, auth.tok, auth.tun, auth.gw, auth.dns, auth.mtu
    );

    if args.encrypt != 1 {
        eprintln!("WARN: data-plane only XOR(1), got {}", args.encrypt);
    }

    let sk = crypto::session_key(&args.user, &args.pass);
    let xk: Vec<u8> = sk[..8].to_vec();
    let route_targets = route_targets(args);

    let _ = iwan::core::util::ip_run_quiet(&["link", "del", &args.tun]);
    let tun_fd = tun::open_tun(&args.tun).context("open tun (must be root)")?;
    tun::set_nonblock(tun_fd);
    println!("tun {} fd={}", args.tun, tun_fd);

    proxy::run_pump(
        tun_fd,
        &args.tun,
        &sock,
        &xk,
        auth.sid,
        auth.tok,
        args.encrypt,
        &args.server,
        &route_targets,
        &auth.tun,
        auth.mtu,
    )?;

    tun::tun_close(tun_fd);
    println!("done.");
    Ok(())
}

fn route_targets(args: &cli::ProxyArgs) -> Vec<String> {
    let mut targets = Vec::new();
    targets.extend(args.proxy_cidr.iter().cloned());
    targets.extend(args.proxy_ip.iter().cloned());
    targets.extend(args.proxy_domain.iter().cloned());
    targets
}
