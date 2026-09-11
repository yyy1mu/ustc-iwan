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
    enlarge_udp_buffers(&s);
    s.set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    Ok(s)
}

#[cfg(unix)]
fn enlarge_udp_buffers(sock: &std::net::UdpSocket) {
    use std::os::fd::AsRawFd;

    const UDP_BUFFER_SIZE: libc::c_int = 16 * 1024 * 1024;
    let fd = sock.as_raw_fd();
    set_buffer(fd, libc::SO_RCVBUF, UDP_BUFFER_SIZE);
    set_buffer(fd, libc::SO_SNDBUF, UDP_BUFFER_SIZE);

    if crate::core::util::debug_enabled() {
        let rcv = get_buffer(fd, libc::SO_RCVBUF);
        let snd = get_buffer(fd, libc::SO_SNDBUF);
        eprintln!("UDP buffers: rcvbuf={rcv} sndbuf={snd} (requested {UDP_BUFFER_SIZE})");
        if rcv < UDP_BUFFER_SIZE || snd < UDP_BUFFER_SIZE {
            eprintln!(
                "  hint: raise net.core.rmem_max and net.core.wmem_max to allow {UDP_BUFFER_SIZE}"
            );
        }
    }
}

#[cfg(unix)]
fn set_buffer(fd: std::os::fd::RawFd, option: libc::c_int, size: libc::c_int) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&size) as libc::socklen_t,
        );
    }
}

#[cfg(unix)]
fn get_buffer(fd: std::os::fd::RawFd, option: libc::c_int) -> libc::c_int {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        );
    }
    value
}

#[cfg(not(unix))]
fn enlarge_udp_buffers(_sock: &std::net::UdpSocket) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn udp_buffer_request_is_applied_or_clamped_upwards() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        enlarge_udp_buffers(&sock);
        let fd = sock.as_raw_fd();
        assert!(get_buffer(fd, libc::SO_RCVBUF) >= 64 * 1024);
        assert!(get_buffer(fd, libc::SO_SNDBUF) >= 64 * 1024);
    }
}

pub fn rand_u32() -> Result<u32> {
    Ok(rand::random())
}

pub fn get_ct(user: &str, pass: &str, ct_pass_hex: Option<&str>) -> Result<[u8; 16]> {
    let Some(hex) = ct_pass_hex else {
        return Ok(crypto::encrypt_password(pass, user));
    };
    let hex = hex.trim().trim_start_matches("0x");
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or_default(), 16))
        .collect::<std::result::Result<Vec<u8>, _>>()
        .context("invalid --ct-pass hex")?;
    if bytes.len() < 16 {
        anyhow::bail!("--ct-pass must be at least 16 bytes");
    }
    let mut ct = [0u8; 16];
    ct.copy_from_slice(&bytes[..16]);
    Ok(ct)
}
