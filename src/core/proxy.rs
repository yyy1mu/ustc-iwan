use super::{crypto, protocol, route, tun};
use anyhow::{Context, Result};
use std::net::{ToSocketAddrs, UdpSocket};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Run the TUN↔UDP data-plane pump. Blocks until Ctrl-C or error.
pub fn run_pump(
    tun_fd: RawFd,
    tun_name: &str,
    sock: &UdpSocket,
    xk: &[u8],
    sid: u16,
    tok: u32,
    enc: u8,
    server: &str,
    route_targets: &[String],
    auth_tun_ip: &str,
    auth_mtu: u16,
) -> Result<()> {
    let (ogw, odev) = route::capture_default().context("cannot detect default route")?;
    if super::util::debug_enabled() {
        eprintln!("default route: via {ogw} dev {odev}");
    }

    let routes = expand_route_targets(route_targets)?;
    if !routes.is_empty() {
        route::setup(
            tun_name,
            auth_tun_ip,
            auth_mtu,
            server,
            &ogw,
            &odev,
            &routes,
        );
        println!(
            "TUN {tun_name} ready: {} route{}",
            routes.len(),
            if routes.len() == 1 { "" } else { "s" }
        );
        if super::util::debug_enabled() {
            for route in &routes {
                eprintln!("route {route} -> dev {tun_name}");
            }
        }
    } else {
        let _ = super::util::ip_run(&["addr", "flush", "dev", tun_name]);
        super::util::ip_run(&["link", "set", tun_name, "up"]);
        super::util::ip_run(&["link", "set", "dev", tun_name, "mtu", &auth_mtu.to_string()]);
        super::util::ip_run(&["addr", "add", &format!("{auth_tun_ip}/24"), "dev", tun_name]);
        println!("tun {tun_name} up with IP {auth_tun_ip}/24 (no route hijack)");
    }

    let running = Arc::new(AtomicBool::new(true));
    let sock_send = sock.try_clone().context("clone send socket")?;
    let sock_recv = sock.try_clone().context("clone recv socket")?;
    sock_recv
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();

    let xk_send = xk.to_vec();
    let xk_recv = xk.to_vec();

    let r1 = running.clone();
    let t1 = std::thread::spawn(move || {
        let mut buf = vec![0u8; 2048];
        let mut pfd = libc::pollfd {
            fd: tun_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if super::util::debug_enabled() {
            eprintln!("[TUN→UDP] started");
        }
        loop {
            if !r1.load(Ordering::Relaxed) {
                break;
            }
            let n = tun::tun_read(tun_fd, &mut buf);
            if n == -1 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    unsafe { libc::poll(&mut pfd, 1, 200) };
                    continue;
                }
                r1.store(false, Ordering::Relaxed);
                break;
            }
            if n <= 0 {
                r1.store(false, Ordering::Relaxed);
                break;
            }
            crypto::xor(&mut buf[..n as usize], &xk_send);
            let h = protocol::pkhdr(protocol::PT_DATA_ENC, enc, sid, tok);
            if sock_send
                .send(&protocol::data_pkt(&h, &buf[..n as usize]))
                .is_err()
            {
                r1.store(false, Ordering::Relaxed);
                break;
            }
        }
        if super::util::debug_enabled() {
            eprintln!("[TUN→UDP] stopped");
        }
    });

    let r2 = running.clone();
    let t2 = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        let mut last_keepalive = Instant::now()
            .checked_sub(KEEPALIVE_INTERVAL)
            .unwrap_or_else(Instant::now);
        if super::util::debug_enabled() {
            eprintln!("[UDP→TUN] started");
        }
        loop {
            if !r2.load(Ordering::Relaxed) {
                break;
            }
            if last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
                let h = protocol::pkhdr(protocol::PT_ECHO_REQ, enc, sid, tok);
                if let Err(e) = sock_recv.send(&protocol::ctrl_pkt(&h, &[])) {
                    eprintln!("[UDP→TUN] keepalive send err: {e}");
                    r2.store(false, Ordering::Relaxed);
                    break;
                }
                last_keepalive = Instant::now();
            }
            match sock_recv.recv(&mut buf) {
                Ok(n) if n >= 8 => {
                    let t = buf[0];
                    if t == protocol::PT_DATA_ENC {
                        crypto::xor(&mut buf[8..n], &xk_recv);
                        tun::tun_write(tun_fd, &buf[8..n]);
                    } else if t == protocol::PT_DATA {
                        tun::tun_write(tun_fd, &buf[8..n]);
                    } else if t == protocol::PT_CLOSE {
                        eprintln!("[UDP→TUN] server sent CLOSE");
                        r2.store(false, Ordering::Relaxed);
                        break;
                    } else if t == protocol::PT_ECHO_REQ {
                        let h = protocol::pkhdr(protocol::PT_ECHO_RES, enc, sid, tok);
                        if let Err(e) = sock_recv.send(&protocol::ctrl_pkt(&h, &[])) {
                            eprintln!("[UDP→TUN] keepalive response err: {e}");
                            r2.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[UDP→TUN] recv err: {e}");
                    r2.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        if super::util::debug_enabled() {
            eprintln!("[UDP→TUN] stopped");
        }
    });

    let rr = running.clone();
    ctrlc::set_handler(move || {
        eprintln!("\nSIGINT — shutting down...");
        rr.store(false, Ordering::Relaxed);
    })
    .context("set SIGINT handler")?;

    println!("TUN proxy running — press Ctrl-C to stop");
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
    }
    t1.join().ok();
    t2.join().ok();

    if !routes.is_empty() {
        route::teardown(tun_name, server, &ogw, &odev, &routes);
    } else {
        let _ = super::util::ip_run(&["addr", "flush", "dev", tun_name]);
        let _ = super::util::ip_run(&["link", "set", tun_name, "down"]);
    }

    let c = protocol::pkhdr(protocol::PT_CLOSE, enc, sid, tok);
    let _ = sock.send(&protocol::ctrl_pkt(&c, &[]));
    if super::util::debug_enabled() {
        eprintln!("CLOSE sent");
    }
    Ok(())
}

fn expand_route_targets(targets: &[String]) -> Result<Vec<String>> {
    let mut routes = Vec::new();
    for target in targets {
        let target = target.trim();
        if target.is_empty() {
            continue;
        }
        if target == "default" || target.contains('/') {
            push_unique(&mut routes, target.to_string());
        } else if target.parse::<std::net::Ipv4Addr>().is_ok() {
            push_unique(&mut routes, format!("{target}/32"));
        } else {
            let mut found = false;
            for addr in (target, 0)
                .to_socket_addrs()
                .with_context(|| format!("resolve domain {target}"))?
            {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    push_unique(&mut routes, format!("{ip}/32"));
                    found = true;
                }
            }
            if !found {
                anyhow::bail!("domain has no IPv4 address: {target}");
            }
        }
    }
    Ok(routes)
}

fn push_unique(routes: &mut Vec<String>, route: String) {
    if !routes.iter().any(|r| r == &route) {
        routes.push(route);
    }
}
