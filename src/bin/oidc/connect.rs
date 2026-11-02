use anyhow::{Context, Result};
use iwan::core::{auth, client, crypto, gcm};
#[cfg(target_os = "linux")]
use iwan::core::{tun, tun_proxy};
use std::io::{self, Write};

use crate::cli;
use crate::config::{LocalConfig, Server};
use crate::{controller, oidc, APP_SECRET, DOMAIN};

pub(crate) fn fetch_config() -> Result<LocalConfig> {
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
                    salt: string_field(s, "salt"),
                    mtu: s["mtu"].as_u64().map(|v| v as u16),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(LocalConfig {
        domain: DOMAIN.to_string(),
        servers,
    })
}

fn string_field(value: &serde_json::Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

fn select_fastest_server<'a>(servers: &'a [Server], bind: Option<&str>) -> Result<&'a Server> {
    if servers.is_empty() {
        anyhow::bail!("no servers available");
    }
    let mut best: Option<(&Server, std::time::Duration)> = None;
    for srv in servers {
        if srv.host.is_empty() {
            continue;
        }
        match auth::ping_server(&srv.host, srv.port, 800, bind) {
            Ok(rtt) => {
                eprintln!("  ping {}:{}  {rtt:?}", srv.host, srv.port);
                if best.is_none_or(|(_, current)| rtt < current) {
                    best = Some((srv, rtt));
                }
            }
            Err(e) => eprintln!("  ping {}:{}  failed: {e}", srv.host, srv.port),
        }
    }
    best.map(|(srv, _)| srv)
        .or_else(|| servers.first())
        .context("no reachable server")
}

pub(crate) fn print_servers(servers: &[Server]) {
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

pub(crate) fn connect_server(cli: &cli::Cli, config: &LocalConfig) -> Result<()> {
    if config.servers.is_empty() {
        anyhow::bail!("no servers in config");
    }

    let dns = iwan::core::dns::DnsResolver::parse(&cli.dns)
        .with_context(|| format!("invalid --dns value {:?}", cli.dns))?;
    let srv = if cli.auto || cli.server.as_deref() == Some("auto") {
        select_fastest_server(&config.servers, cli.bind.as_deref())?
    } else {
        select_server(&config.servers, cli.server.as_deref())?
    };
    anyhow::ensure!(!srv.host.is_empty(), "selected server has no host");

    let password = gcm::decrypt_password(&srv.password, APP_SECRET, &config.domain, &srv.username)
        .context("decrypt server password")?;
    eprintln!(
        "\n  Connecting to {} ({}:{})...",
        srv.name, srv.host, srv.port
    );

    let salt = if cli.salt.is_empty() {
        srv.salt.as_str()
    } else {
        cli.salt.as_str()
    };
    #[cfg(target_os = "linux")]
    let open_mtu = srv.mtu.unwrap_or(cli.tun_mtu);
    #[cfg(not(target_os = "linux"))]
    let open_mtu = srv.mtu.unwrap_or(1400u16);
    let pipe = (cli.pipeid != 0).then_some((cli.pipeidx, cli.pipeid));
    let srlink = cli
        .sr_links
        .first()
        .copied()
        .or_else(|| (cli.sr_encrypt_mode != 0).then_some(1));
    let sr_key_mode =
        iwan::core::sr::SrKeyMode::parse(&cli.sr_key_mode).context("invalid --sr-key-mode")?;
    let sr = iwan::core::sr::SrConfig::from_options(
        &cli.sr_password,
        &cli.sr_links,
        cli.sr_encrypt_mode,
        sr_key_mode,
    )
    .map(|sr| sr.with_local_id(cli.sr_local_id));

    let session = client::open(&client::SessionConfig {
        server: &srv.host,
        port: srv.port,
        user: &srv.username,
        pass: &password,
        ct_pass: None,
        salt,
        mtu: open_mtu,
        encrypt: cli.encrypt,
        bind: cli.bind.as_deref(),
        pipe,
        srlink,
        sr,
    })?;

    eprintln!(
        "  OK  tun={} gw={} dns={} mtu={} enc={} ipv6={:?} av={:?}",
        session.auth.tun,
        session.auth.gw,
        session.auth.dns,
        session.auth.mtu,
        session.encryption,
        session.auth.ipv6,
        session.auth.auth_verify
    );

    if cli.socks || cli.http {
        return run_local_proxy(cli, session, dns);
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
        let outcome = tun_proxy::run_pump(tun_proxy::PumpConfig {
            tun_fd,
            tun_name: &cli.tun,
            sock: &session.sock,
            xor_key: &session.xor_key,
            aes_key: &session.aes_key,
            sid: session.auth.sid,
            token: session.auth.tok,
            encryption: session.encryption,
            server: &srv.host,
            route_targets: &route_targets,
            tun_ip: &session.auth.tun,
            tun_ipv6: session.auth.ipv6,
            mtu: session.auth.mtu,
            sr: session.sr,
            duplicate: cli.duplicate || session.auth.duppkt.unwrap_or(0) != 0,
        })?;

        tun::tun_close(tun_fd);
        match outcome {
            tun_proxy::PumpOutcome::Stopped => Ok(()),
            tun_proxy::PumpOutcome::ServerClosed => {
                anyhow::bail!("VPN server closed the tunnel")
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    unreachable!("non-Linux builds always use SOCKS5 or HTTP")
}

#[cfg(target_os = "linux")]
fn route_targets(cli: &cli::Cli) -> Vec<String> {
    let mut targets = Vec::new();
    targets.extend(cli.proxy_cidr.iter().cloned());
    targets.extend(cli.proxy_ip.iter().cloned());
    targets.extend(cli.proxy_domain.iter().cloned());
    targets
}

fn run_local_proxy(
    cli: &cli::Cli,
    session: client::ClientSession,
    dns: iwan::core::dns::DnsResolver,
) -> Result<()> {
    let inner_ip = session
        .auth
        .tun
        .parse()
        .context("server returned invalid tunnel IPv4 address")?;
    let gateway = session
        .auth
        .gw
        .parse()
        .context("server returned invalid gateway IPv4 address")?;
    let (protocol, listen) = if cli.http {
        (
            iwan::core::local_proxy::ProxyProtocol::Http,
            cli.http_listen,
        )
    } else {
        (
            iwan::core::local_proxy::ProxyProtocol::Socks5,
            cli.socks_listen,
        )
    };
    iwan::core::local_proxy::run(
        &session.sock,
        iwan::core::local_proxy::ProxyConfig {
            listen,
            protocol,
            inner_ip,
            gateway,
            mtu: usize::from(session.auth.mtu.min(cli.proxy_mtu)),
            xor_key: &session.xor_key,
            aes_key: &session.aes_key,
            sid: session.auth.sid,
            token: session.auth.tok,
            encryption: session.encryption,
            sr: session.sr,
            duplicate: cli.duplicate || session.auth.duppkt.unwrap_or(0) != 0,
            dns,
        },
    )
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
            salt: String::new(),
            mtu: None,
        }
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
