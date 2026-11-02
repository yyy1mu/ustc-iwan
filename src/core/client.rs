//! Shared client-side VPN handshake.
//!
//! All CLI entry points (manual auth/proxy, SOCKS/HTTP, OIDC) use this module
//! instead of re-implementing OPEN/AUTH_VERIFY/ACK handling.

use super::auth;
use super::crypto;
use super::sr::SrConfig;
use anyhow::{Context, Result};
use std::net::UdpSocket;
use std::time::Duration;

pub struct SessionConfig<'a> {
    pub server: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub pass: &'a str,
    pub ct_pass: Option<&'a str>,
    pub salt: &'a str,
    pub mtu: u16,
    pub encrypt: u8,
    pub bind: Option<&'a str>,
    pub pipe: Option<(u16, u16)>,
    pub srlink: Option<u32>,
    pub sr: Option<SrConfig>,
}

pub struct ClientSession {
    pub sock: UdpSocket,
    pub auth: auth::AuthResult,
    pub xor_key: Vec<u8>,
    pub aes_key: Vec<u8>,
    pub encryption: u8,
    pub sr: Option<SrConfig>,
}

pub fn open(config: &SessionConfig<'_>) -> Result<ClientSession> {
    let ct = auth::get_ct(config.user, config.pass, config.ct_pass, config.salt)?;
    let nonce = auth::rand_u32();
    let open = auth::build_open(
        config.user,
        &ct,
        config.mtu,
        config.encrypt,
        config.pipe,
        config.srlink,
        nonce,
    );
    let sock = auth::udp_connect(config.server, config.port, 3000, config.bind)?;

    let mut result = None;
    let mut last_error = None;
    for attempt in 0..=3 {
        sock.send(&open).context("send OPEN")?;
        println!("[{attempt}] -> OPEN");
        let mut buf = [0u8; 4096];
        match sock.recv(&mut buf) {
            Ok(n) => match auth::parse_ack(&buf[..n], nonce) {
                Ok(value) => {
                    result = Some(value);
                    break;
                }
                Err(e) => last_error = Some(e),
            },
            Err(e) => last_error = Some(anyhow::anyhow!("timeout: {e}")),
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let auth =
        result.ok_or_else(|| last_error.unwrap_or_else(|| anyhow::anyhow!("auth failed")))?;
    let encryption = auth.enc.unwrap_or(config.encrypt);
    if encryption > 2 {
        anyhow::bail!("server selected unsupported encrypt mode {encryption}");
    }
    let key = crypto::session_key(config.user, config.pass);
    Ok(ClientSession {
        sock,
        auth,
        xor_key: key[..8].to_vec(),
        aes_key: key.to_vec(),
        encryption,
        sr: config.sr.clone(),
    })
}
