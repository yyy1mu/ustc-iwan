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
    if cli.socks && !do_connect {
        anyhow::bail!("--socks requires --connect or --all");
    }
    #[cfg(not(target_os = "linux"))]
    if do_connect && !cli.socks {
        anyhow::bail!("--socks is required for --connect or --all on this platform");
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

#[derive(serde::Serialize, serde::Deserialize)]
struct Server {
    #[serde(default)]
    name: String,
    #[serde(default)]
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default, rename = "passWord")]
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LocalConfig {
    #[serde(default = "default_domain")]
    domain: String,
    #[serde(default)]
    servers: Vec<Server>,
}

fn default_port() -> u16 {
    6001
}

fn default_domain() -> String {
    DOMAIN.to_string()
}

fn string_field(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
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
    if iwan::core::util::debug_enabled() {
        eprintln!("  device_id={device_id}");
    }

    let dev_body = serde_json::json!({
        "domain": DOMAIN, "type": "android", "oem_name": "panabit",
        "device_id": device_id, "userName": username,
        "serverlist_version": "0", "ipfilter_version": "0", "branding_version": "0",
    });

    eprint!("  Registering device... ");
    io::stdout().flush().ok();
    let (st, resp) = controller::post(&agent, "/m/auth", &dev_body, &kp_token)?;
    if st != 200 {
        anyhow::bail!("fail HTTP {st}: {resp}");
    }
    eprintln!("OK");

    let mut kp_body = dev_body.clone();
    kp_body["type"] = serde_json::Value::String("keepalive".into());
    let (st, _) = controller::post(&agent, "/m/keepalive", &kp_body, &kp_token)?;
    if st != 200 {
        anyhow::bail!("keepalive failed HTTP {st}");
    }

    eprint!("  Fetching server config... ");
    io::stdout().flush().ok();
    let (st, resp) = controller::post(&agent, "/m/config", &dev_body, &kp_token)?;
    if st != 200 {
        anyhow::bail!("fail HTTP {st}: {resp}");
    }
    eprintln!("OK");

    let servers: Vec<Server> = resp["serverlist"]["serverlist"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|s| Server {
                    name: string_field(s, "name"),
                    host: string_field(s, "serverName"),
                    port: s["serverPort"].as_u64().unwrap_or(6001) as u16,
                    username: string_field(s, "userName"),
                    password: string_field(s, "passWord"),
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
    std::fs::write(path, serde_json::to_string_pretty(config)?).context("write config")?;
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
    serde_json::from_str(&content).context("parse config")
}

fn connect_server(cli: &cli::Cli, config: &LocalConfig) -> Result<()> {
    if config.servers.is_empty() {
        anyhow::bail!("no servers in config");
    }

    let dns = iwan::core::socks::DnsResolver::parse(&cli.dns)
        .with_context(|| format!("invalid --dns value {:?}", cli.dns))?;
    let srv = select_server(&config.servers, cli.server.as_deref())?;
    anyhow::ensure!(!srv.host.is_empty(), "selected server has no host");

    let password = gcm::decrypt_password(&srv.password, APP_SECRET, &config.domain, &srv.username);
    eprintln!(
        "\n  Connecting to {} ({}:{})...",
        srv.name, srv.host, srv.port
    );

    let ct = auth::get_ct(&srv.username, &password, None)?;
    let nonce = auth::rand_u32()?;
    let open = auth::build_open(&srv.username, &ct, 1400, cli.encrypt, nonce);
    let sock = auth::udp_connect(&srv.host, srv.port, 3000)?;

    let auth_result = {
        let mut result = None;
        for i in 0u32..=3 {
            sock.send(&open)?;
            if iwan::core::util::debug_enabled() {
                eprintln!("  auth attempt {}", i + 1);
            }
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

    let sk = crypto::session_key(&srv.username, &password);
    let xk: Vec<u8> = sk[..8].to_vec();

    if cli.socks {
        return run_socks(cli, &sock, &xk, &auth_result, dns);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = iwan::core::util::ip_run_quiet(&["link", "del", &cli.tun]);
        let tun_fd = tun::open_tun(&cli.tun).context("open tun (must be root or CAP_NET_ADMIN)")?;
        tun::set_nonblock(tun_fd);
        if iwan::core::util::debug_enabled() {
            eprintln!("  tun {} fd={}", cli.tun, tun_fd);
        }

        let route_targets = route_targets(cli);

        proxy::run_pump(proxy::PumpConfig {
            tun_fd,
            tun_name: &cli.tun,
            sock: &sock,
            xor_key: &xk,
            sid: auth_result.sid,
            token: auth_result.tok,
            encryption: cli.encrypt,
            server: &srv.host,
            route_targets: &route_targets,
            tun_ip: &auth_result.tun,
            mtu: auth_result.mtu,
        })?;

        tun::tun_close(tun_fd);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    unreachable!("non-Linux builds always use SOCKS5")
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
    dns: iwan::core::socks::DnsResolver,
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
            dns,
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
    #[cfg(target_os = "windows")]
    {
        if let Some(home) = std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return PathBuf::from(home);
        }
        if let (Some(drive), Some(path)) = (
            std::env::var_os("HOMEDRIVE").filter(|value| !value.is_empty()),
            std::env::var_os("HOMEPATH").filter(|value| !value.is_empty()),
        ) {
            let mut home = PathBuf::from(drive);
            home.push(path);
            return home;
        }
    }

    #[cfg(target_os = "linux")]
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            if let Some(home) = passwd_home(&sudo_user) {
                return home;
            }
            return PathBuf::from(format!("/home/{sudo_user}"));
        }
    }

    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(target_os = "linux")]
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

fn print_servers(servers: &[Server]) {
    for (idx, s) in servers.iter().enumerate() {
        println!("{:>2}. {:30} {}:{}", idx + 1, s.name, s.host, s.port);
    }
}

fn select_server<'a>(servers: &'a [Server], choice: Option<&str>) -> Result<&'a Server> {
    if let Some(choice) = choice {
        if let Ok(index) = choice.parse::<usize>() {
            return index
                .checked_sub(1)
                .and_then(|i| servers.get(i))
                .with_context(|| format!("server index {index} out of range 1-{}", servers.len()));
        }
        return servers
            .iter()
            .find(|s| s.name.contains(choice))
            .with_context(|| format!("no server name contains \"{choice}\""));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn server(name: &str, host: &str, port: u16) -> Server {
        Server {
            name: name.to_string(),
            host: host.to_string(),
            port,
            username: "user".to_string(),
            password: "cipher".to_string(),
        }
    }

    #[test]
    fn config_round_trips_existing_format() {
        let json = r#"{
            "domain": "iwan.ustc",
            "servers": [
                {"name": "教育网线路", "host": "1.2.3.4", "port": 6001,
                 "username": "user", "passWord": "cipher"}
            ]
        }"#;
        let config: LocalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.domain, "iwan.ustc");
        assert_eq!(config.servers[0].port, 6001);

        let saved = serde_json::to_value(&config).unwrap();
        assert_eq!(saved["servers"][0]["passWord"], "cipher");
        assert_eq!(saved["servers"][0]["host"], "1.2.3.4");
    }

    #[test]
    fn select_server_matches_index_and_name() {
        let servers = vec![
            server("教育网线路", "a", 6001),
            server("电信线路", "b", 6002),
        ];
        assert_eq!(select_server(&servers, Some("2")).unwrap().host, "b");
        assert_eq!(select_server(&servers, Some("电信")).unwrap().port, 6002);
        assert!(select_server(&servers, Some("移动")).is_err());
        assert!(select_server(&servers, Some("3")).is_err());
    }
}
