use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::DOMAIN;

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct Server {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) host: String,
    #[serde(default = "default_port")]
    pub(crate) port: u16,
    #[serde(default)]
    pub(crate) username: String,
    #[serde(default, rename = "passWord")]
    pub(crate) password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalConfig {
    #[serde(default = "default_domain")]
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) servers: Vec<Server>,
}

fn default_port() -> u16 {
    6001
}

fn default_domain() -> String {
    DOMAIN.to_string()
}

pub(crate) fn save_config(path: &std::path::Path, config: &LocalConfig) -> Result<()> {
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

pub(crate) fn load_config(path: &std::path::Path) -> Result<LocalConfig> {
    let content = std::fs::read_to_string(path).with_context(|| {
        format!(
            "config file not found or unreadable: {}; run iwan-client-oidc --fetch first",
            path.display()
        )
    })?;
    serde_json::from_str(&content).context("parse config")
}

pub(crate) fn resolve_dir(dir: &str) -> PathBuf {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
