mod cli;
mod controller;
mod oidc;

use anyhow::{Context, Result};
use clap::Parser;
use iwan::core::{auth, crypto, gcm};
#[cfg(target_os = "linux")]
use iwan::core::{proxy, tun};
use std::io::{self, Write};
use std::path::PathBuf;

const DOMAIN: &str = "iwan.ustc";
const APP_SECRET: &str = "ca6a3532abd2986a03b86b3a";

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    if !(cli.fetch || cli.list || cli.connect || cli.all) {
        anyhow::bail!("choose one action: --fetch, --list, --connect, or --all");
    }

    let path = resolve_dir(&cli.config_dir).join("servers.json");
    let do_fetch = cli.fetch || cli.all;
    let do_list = cli.list || cli.all;
    let do_connect = cli.connect || cli.all;
    #[cfg(target_os = "linux")]
    if cli.socks && !do_connect {
        anyhow::bail!("--socks requires --connect or --all");
    }

    let config = if do_fetch {
        let config = fetch_config()?;
        save_config(&path, &config)?;
        config
    } else {
        load_config(&path)?
    };

    if do_list || do_connect {
        print_servers(&config.servers);
    }
    if do_connect {
        connect_server(&cli, &config)?;
    }

    Ok(())
}

struct LocalConfig {
    domain: String,
    servers: Vec<serde_json::Value>,
}

fn fetch_config() -> Result<LocalConfig> {
    let agent = controller::http_agent();

    let (kp_token, username) = oidc::run(&agent)?;

    let device_id = {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut b);
        crypto::hex(&b)
    };
    eprintln!("  device_id = {device_id}");

    let dev_body = serde_json::json!({
        "domain": DOMAIN, "type": "android", "oem_name": "panabit",
        "device_id": device_id, "userName": username,
        "serverlist_version": "0", "ipfilter_version": "0", "branding_version": "0",
    });

    // ② /m/auth
    eprint!("  /m/auth... ");
    io::stdout().flush().ok();
    let (st, resp) = controller::post(&agent, "/m/auth", &dev_body, &kp_token)?;
    if st != 200 {
        anyhow::bail!("fail HTTP {st}: {resp}");
    }
    eprintln!("OK");

    // ③ /m/keepalive
    eprint!("  /m/keepalive... ");
    io::stdout().flush().ok();
    let mut kp_body = dev_body.clone();
    kp_body["type"] = serde_json::Value::String("keepalive".into());
    let (st, _) = controller::post(&agent, "/m/keepalive", &kp_body, &kp_token)?;
    eprintln!("HTTP {st}");

    // ④ /m/config
    eprint!("  /m/config... ");
    io::stdout().flush().ok();
    let (st, resp) = controller::post(&agent, "/m/config", &dev_body, &kp_token)?;
    if st != 200 {
        anyhow::bail!("fail HTTP {st}: {resp}");
    }
    eprintln!("OK");

    let servers: Vec<serde_json::Value> = resp["serverlist"]["serverlist"]
        .as_array()
        .map(|sl| {
            sl.iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s["name"], "host": s["serverName"], "port": s["serverPort"],
                        "username": s["userName"], "passWord": s["passWord"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(LocalConfig {
        domain: DOMAIN.to_string(),
        servers,
    })
}

fn save_config(path: &std::path::Path, config: &LocalConfig) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).context("create config dir")?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::json!({
            "domain": config.domain,
            "servers": config.servers,
        }))?,
    )
    .context("write config")?;
    eprintln!(
        "  Saved {} server(s) to {}",
        config.servers.len(),
        path.display()
    );
    Ok(())
}

fn load_config(path: &std::path::Path) -> Result<LocalConfig> {
    let content = std::fs::read_to_string(path).with_context(|| {
        format!(
            "config file not found or unreadable: {}; run iwan-client-oidc --fetch first",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_str(&content).context("parse config")?;
    let domain = value["domain"].as_str().unwrap_or(DOMAIN).to_string();
    let servers = value["servers"]
        .as_array()
        .cloned()
        .context("config missing servers array")?;
    Ok(LocalConfig { domain, servers })
}

fn connect_server(cli: &cli::Cli, config: &LocalConfig) -> Result<()> {
    if config.servers.is_empty() {
        anyhow::bail!("no servers in config");
    }

    let srv = select_server(&config.servers)?;
    let host = srv["host"].as_str().context("missing host")?;
    let port = srv["port"].as_u64().unwrap_or(6001) as u16;
    let srv_user = srv["username"].as_str().unwrap_or("");
    let encrypted_pw = srv["passWord"].as_str().unwrap_or("");
    let name = srv["name"].as_str().unwrap_or("");

    let password = gcm::decrypt_password(encrypted_pw, APP_SECRET, &config.domain, srv_user);
    eprintln!("\n  Connecting to {name} ({host}:{port})...");

    let ct = auth::get_ct(srv_user, &password, &None);
    let nonce = auth::rand_u32()?;
    let open = auth::build_open(srv_user, &ct, 1400, cli.encrypt, nonce);
    let sock = auth::udp_connect(host, port, 3000)?;

    let auth_result = {
        let mut result = None;
        for i in 0u32..=3 {
            sock.send(&open)?;
            eprintln!("  [{i}] -> OPEN");
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
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
        result.context("auth failed")?
    };

    eprintln!(
        "  OK  tun={} gw={} dns={} mtu={}",
        auth_result.tun, auth_result.gw, auth_result.dns, auth_result.mtu
    );

    let sk = crypto::session_key(srv_user, &password);
    let xk: Vec<u8> = sk[..8].to_vec();

    if socks_mode(cli) {
        return run_socks(cli, &sock, &xk, &auth_result);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = iwan::core::util::ip_run(&["link", "del", &cli.tun]);
        let tun_fd = tun::open_tun(&cli.tun).context("open tun (must be root or CAP_NET_ADMIN)")?;
        tun::set_nonblock(tun_fd);
        eprintln!("  tun {} fd={}", cli.tun, tun_fd);

        let route_targets = route_targets(cli);

        proxy::run_pump(
            tun_fd,
            &cli.tun,
            &sock,
            &xk,
            auth_result.sid,
            auth_result.tok,
            cli.encrypt,
            host,
            &route_targets,
            &auth_result.tun,
            auth_result.mtu,
        )?;

        tun::tun_close(tun_fd);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    unreachable!("non-Linux builds always use SOCKS5")
}

#[cfg(target_os = "linux")]
fn socks_mode(cli: &cli::Cli) -> bool {
    cli.socks
}

#[cfg(not(target_os = "linux"))]
fn socks_mode(_cli: &cli::Cli) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn route_targets(cli: &cli::Cli) -> Vec<String> {
    let mut targets = Vec::new();
    targets.extend(cli.proxy_cidr.iter().cloned());
    targets.extend(cli.proxy_ip.iter().cloned());
    targets.extend(cli.proxy_domain.iter().cloned());
    targets
}

fn run_socks(
    cli: &cli::Cli,
    sock: &std::net::UdpSocket,
    xor_key: &[u8],
    auth_result: &auth::AuthResult,
) -> Result<()> {
    let inner_ip = auth_result
        .tun
        .parse()
        .context("server returned invalid tunnel IPv4 address")?;
    let gateway = auth_result
        .gw
        .parse()
        .context("server returned invalid gateway IPv4 address")?;
    iwan::core::socks::run(
        sock,
        iwan::core::socks::SocksConfig {
            listen: cli.socks_listen,
            inner_ip,
            gateway,
            mtu: usize::from(auth_result.mtu.min(cli.socks_mtu)),
            xor_key,
            sid: auth_result.sid,
            token: auth_result.tok,
            encryption: cli.encrypt,
        },
    )
}

fn resolve_dir(dir: &str) -> PathBuf {
    if let Some(rest) = dir.strip_prefix("~/") {
        default_home().join(rest)
    } else {
        PathBuf::from(dir)
    }
}

fn default_home() -> PathBuf {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            if let Some(home) = passwd_home(&sudo_user) {
                return home;
            }
            return PathBuf::from(format!("/home/{sudo_user}"));
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

fn passwd_home(user: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("getent")
        .args(["passwd", user])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8(output.stdout).ok()?;
    line.split(':').nth(5).map(PathBuf::from)
}

fn print_servers(servers: &[serde_json::Value]) {
    for (idx, s) in servers.iter().enumerate() {
        println!(
            "{:>2}. {:30} {}:{}",
            idx + 1,
            s["name"].as_str().unwrap_or(""),
            s["host"].as_str().unwrap_or(""),
            s["port"].as_u64().unwrap_or(0)
        );
    }
}

fn select_server(servers: &[serde_json::Value]) -> Result<&serde_json::Value> {
    loop {
        print!("  Select server [1-{}]: ", servers.len());
        io::stdout().flush().ok();

        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("read server selection")?;

        if let Ok(n) = line.trim().parse::<usize>() {
            if (1..=servers.len()).contains(&n) {
                return Ok(&servers[n - 1]);
            }
        }
        eprintln!("  invalid selection");
    }
}
