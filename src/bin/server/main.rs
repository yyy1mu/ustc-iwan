mod cli;
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
mod downlink;
#[cfg(target_os = "linux")]
mod fragment;
#[cfg(target_os = "linux")]
mod handler;
#[cfg(target_os = "linux")]
mod nat;
#[cfg(target_os = "linux")]
mod session;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
use clap::Parser;
#[cfg(target_os = "linux")]
use iwan::core::tun;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, UdpSocket};
#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    let users = load_users(&cli.users)?;
    if users.is_empty() {
        anyhow::bail!("no users loaded from {}", cli.users);
    }

    let (subnet_ip, prefix) = parse_subnet(&cli.subnet)?;

    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    println!("ip_forward=1");

    let _ = iwan::core::util::ip_run_quiet(&["link", "del", &cli.tun]);
    let tun_fd = tun::open_tun(&cli.tun).context("open tun")?;
    tun::set_nonblock(tun_fd);
    println!("tun {} fd={}", cli.tun, tun_fd);
    configure_tun(&cli, prefix);
    let nat_added = nat::setup(&cli.subnet, &cli.nat_if);

    let next_ip = AtomicU32::new(u32::from(subnet_ip) + 2);
    let next_ipv6 = AtomicU32::new(1);
    let sr_key_mode = iwan::core::sr::SrKeyMode::parse(&cli.sr_key_mode)
        .with_context(|| format!("invalid --sr-key-mode {}", cli.sr_key_mode))?;
    let sr = iwan::core::sr::SrConfig::from_options(
        &cli.sr_password,
        &cli.sr_links,
        cli.sr_encrypt_mode,
        sr_key_mode,
    );
    let sessions: handler::SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let fragments = Mutex::new(HashMap::new());

    let sock = match UdpSocket::bind(format!("[::]:{}", cli.port)) {
        Ok(sock) => {
            println!("listening UDP [::]:{} (dual-stack)", cli.port);
            sock
        }
        Err(_) => {
            let sock = UdpSocket::bind(format!("0.0.0.0:{}", cli.port)).context("bind UDP")?;
            println!("listening UDP 0.0.0.0:{} (IPv4 only)", cli.port);
            sock
        }
    };
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    println!("server ready.");

    let ctx = handler::ServerContext {
        users: &users,
        sessions: &sessions,
        fragments: &fragments,
        next_ip: &next_ip,
        next_ipv6: &next_ipv6,
        server_ip: cli.server_ip,
        server_ipv6: cli.server_ipv6,
        dns: cli.dns,
        dns2: cli.dns2,
        dns_ipv6: cli.dns_ipv6,
        sr: sr.as_ref(),
        fragment: cli.fragment,
        salt: &cli.salt,
        duppkt: cli.duppkt,
        sock: &sock,
        tun: tun_fd,
    };

    let mut udp_buf = vec![0u8; 65535];
    let mut tun_buf = vec![0u8; 65535];

    let running = Arc::new(AtomicBool::new(true));
    let shutdown = running.clone();
    ctrlc::set_handler(move || {
        println!("\nexiting...");
        shutdown.store(false, Ordering::Relaxed);
    })
    .ok();

    let mut last_reap = Instant::now();
    loop {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        match sock.recv_from(&mut udp_buf) {
            Ok((n, addr)) => handler::handle_udp(&udp_buf[..n], addr, &ctx),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("udp err: {e}");
                break;
            }
        }
        if last_reap.elapsed() >= Duration::from_secs(1) {
            handler::reap_sessions(&sessions, Duration::from_secs(120));
            fragment::reap_fragments(&fragments, Duration::from_secs(30));
            last_reap = Instant::now();
        }
        // Drain the TUN queue. Reading only one packet per loop makes queued
        // downlink wait for the next 100 ms UDP timeout, which caps downlink
        // at ~10 packets/s and causes multi-second TCP stalls under load.
        let mut drained = 0;
        loop {
            let r = tun::tun_read(tun_fd, &mut tun_buf);
            if r > 0 {
                downlink::handle(&mut tun_buf[..r as usize], &ctx);
                drained += 1;
                if drained >= 256 {
                    break;
                }
            } else {
                if r < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        eprintln!("tun read err: {e}");
                    }
                }
                break;
            }
        }
    }
    let _ = iwan::core::util::ip_run_quiet(&["link", "del", &cli.tun]);
    if nat_added {
        nat::remove(&cli.subnet, &cli.nat_if);
    }
    println!("server stopped.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // Parse first so --help and --version work on every platform.
    let _ = cli::Cli::parse();
    eprintln!("iwan-server is only supported on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn parse_subnet(spec: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = spec.split_once('/').unwrap_or((spec, "16"));
    let ip = ip
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid subnet {spec}"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid subnet {spec}"))?;
    anyhow::ensure!(prefix <= 32, "subnet prefix must be <= 32");
    Ok((ip, prefix))
}

#[cfg(target_os = "linux")]
fn load_users(path: &str) -> Result<HashMap<String, String>> {
    let content = std::fs::read_to_string(path).context("read users file")?;
    let mut users = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((user, pass)) = line.split_once(':') {
            users.insert(user.trim().to_string(), pass.trim().to_string());
        }
    }
    println!("loaded {} users", users.len());
    Ok(users)
}

#[cfg(target_os = "linux")]
fn configure_tun(cli: &cli::Cli, prefix: u8) {
    use iwan::core::util::ip_run;
    let _ = ip_run(&["addr", "flush", "dev", &cli.tun]);
    ip_run(&["link", "set", &cli.tun, "up"]);
    ip_run(&["link", "set", "dev", &cli.tun, "mtu", &cli.mtu.to_string()]);
    ip_run(&[
        "addr",
        "add",
        &format!("{}/{}", cli.server_ip, prefix),
        "dev",
        &cli.tun,
    ]);
    ip_run(&[
        "-6",
        "addr",
        "add",
        &format!("{}/{}", cli.server_ipv6, cli.ipv6_prefix),
        "dev",
        &cli.tun,
    ]);
    ip_run(&["-6", "route", "replace", &cli.ipv6_subnet, "dev", &cli.tun]);
}
