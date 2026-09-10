#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod handler;
#[cfg(target_os = "linux")]
mod session;

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use iwan::core::tun;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, UdpSocket};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU32;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Duration;

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
    setup_nat(&cli.subnet, &cli.nat_if);

    let _ = iwan::core::util::ip_run_quiet(&["link", "del", &cli.tun]);
    let tun_fd = tun::open_tun(&cli.tun).context("open tun")?;
    tun::set_nonblock(tun_fd);
    println!("tun {} fd={}", cli.tun, tun_fd);
    configure_tun(&cli, prefix);

    let next_ip = AtomicU32::new(u32::from(subnet_ip) + 2);
    let sessions: handler::SessionMap = Arc::new(Mutex::new(HashMap::new()));

    let sock = UdpSocket::bind(format!("0.0.0.0:{}", cli.port)).context("bind UDP")?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    println!("listening UDP 0.0.0.0:{}", cli.port);
    println!("server ready.");

    let ctx = handler::ServerContext {
        users: &users,
        sessions: &sessions,
        next_ip: &next_ip,
        server_ip: cli.server_ip,
        dns: cli.dns,
        sock: &sock,
        tun: tun_fd,
    };

    let mut udp_buf = vec![0u8; 65535];
    let mut tun_buf = vec![0u8; 65535];

    ctrlc::set_handler(move || {
        println!("\nexiting...");
        std::process::exit(0);
    })
    .ok();

    loop {
        match sock.recv_from(&mut udp_buf) {
            Ok((n, addr)) => handler::handle_udp(&udp_buf[..n], addr, &ctx),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("udp err: {e}");
                break;
            }
        }
        let r = tun::tun_read(tun_fd, &mut tun_buf);
        if r > 0 {
            handler::handle_tun_downlink(&mut tun_buf[..r as usize], &sessions, &sock);
        } else if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::WouldBlock {
                eprintln!("tun read err: {e}");
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
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
fn setup_nat(subnet: &str, nat_if: &str) {
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            nat_if,
            "-j",
            "MASQUERADE",
        ])
        .status();
    let ok = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            nat_if,
            "-j",
            "MASQUERADE",
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if ok {
        println!("iptables: MASQUERADE {subnet} -> {nat_if}");
    }
}

#[cfg(target_os = "linux")]
fn configure_tun(cli: &cli::Cli, prefix: u8) {
    use iwan::core::util::ip_run;
    let _ = ip_run(&["addr", "flush", "dev", &cli.tun]);
    ip_run(&["link", "set", &cli.tun, "up"]);
    ip_run(&[
        "addr",
        "add",
        &format!("{}/{}", cli.server_ip, prefix),
        "dev",
        &cli.tun,
    ]);
}
