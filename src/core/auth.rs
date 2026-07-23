use super::{crypto, protocol};
use anyhow::{Context, Result};
use std::time::Duration;

pub struct AuthResult {
    pub sid: u16,
    pub tok: u32,
    pub tun: String,
    pub gw: String,
    pub dns: String,
    pub mtu: u16,
}

pub fn build_open(user: &str, ctp: &[u8; 16], mtu: u16, enc: u8, nonce: u32) -> Vec<u8> {
    let mut pl = Vec::new();
    pl.extend(protocol::tlv(protocol::T_MTU, &mtu.to_be_bytes()));
    pl.extend(protocol::tlv(protocol::T_USERNAME, user.as_bytes()));
    pl.extend(protocol::tlv(protocol::T_PASSWORD, ctp));
    pl.extend(protocol::tlv(protocol::T_ENCRYPT, &[enc]));
    pl.extend(protocol::tlv(protocol::T_AUTH_VERIFY, &nonce.to_be_bytes()));
    let h = protocol::pkhdr(protocol::PT_OPEN, enc, 0, 0);
    protocol::ctrl_pkt(&h, &pl)
}

pub fn parse_ack(buf: &[u8], expect_nonce: u32) -> Result<AuthResult> {
    if buf.len() < 24 {
        anyhow::bail!("too short");
    }
    let t = buf[0];
    let sid = u16::from_be_bytes([buf[2], buf[3]]);
    let tok = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

    if t == protocol::PT_OPEN_REJECT {
        anyhow::bail!("OPEN_REJECT: {}", String::from_utf8_lossy(&buf[24..]));
    }
    if t != protocol::PT_OPEN_ACK {
        anyhow::bail!(
            "unexpected type 0x{:02x} tlvs={}",
            t,
            crypto::hex(&buf[24..])
        );
    }
    if !protocol::verify_sig(buf) {
        anyhow::bail!("bad sig");
    }

    let mut tun = String::new();
    let mut gw = String::new();
    let mut dns = String::new();
    let mut mtu: u16 = 1400;
    for (tt, v) in protocol::parse_tlvs(&buf[24..]) {
        match tt {
            protocol::T_IP => tun = protocol::ip_to_string(&v),
            protocol::T_GATEWAY => gw = protocol::ip_to_string(&v),
            protocol::T_DNS => dns = protocol::ip_to_string(&v),
            protocol::T_MTU if v.len() >= 2 => mtu = u16::from_be_bytes([v[0], v[1]]),
            protocol::T_AUTH_VERIFY => {
                if v.len() != 4 {
                    anyhow::bail!("AV wrong len");
                }
                let echo = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                if echo != expect_nonce {
                    anyhow::bail!("AV mismatch {:08x}", echo);
                }
            }
            _ => {}
        }
    }
    Ok(AuthResult {
        sid,
        tok,
        tun,
        gw,
        dns,
        mtu,
    })
}

pub fn udp_connect(host: &str, port: u16, timeout_ms: u64) -> Result<std::net::UdpSocket> {
    let a: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .context("invalid address")?;
    let s = std::net::UdpSocket::bind("0.0.0.0:0").context("bind UDP")?;
    s.connect(a).context("connect UDP")?;
    s.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    Ok(s)
}

pub fn rand_u32() -> Result<u32> {
    Ok(rand::random())
}

pub fn get_ct(user: &str, pass: &str, ct_pass_hex: &Option<String>) -> [u8; 16] {
    if let Some(ref h) = ct_pass_hex {
        let h = h.trim_start_matches("0x");
        let b: Vec<u8> = (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect();
        let mut o = [0u8; 16];
        o.copy_from_slice(&b[..16]);
        o
    } else {
        crypto::encrypt_password(pass, user)
    }
}
