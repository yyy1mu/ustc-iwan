use super::{crypto, protocol};
use anyhow::{Context, Result};
use std::net::Ipv6Addr;
use std::time::Duration;

pub struct AuthResult {
    pub sid: u16,
    pub tok: u32,
    pub tun: String,
    pub gw: String,
    pub dns: String,
    pub dns2: Option<String>,
    pub mtu: u16,
    pub enc: Option<u8>,
    pub ipv6: Option<Ipv6Addr>,
    pub dns6: Option<Ipv6Addr>,
    pub gw6: Option<Ipv6Addr>,
    pub duppkt: Option<u8>,
    pub auth_verify: Option<u32>,
}

/// Build a new-protocol OPEN. `pipe` is `(pipeidx, pipeid)`; `srlink` is the
/// first SR link label. Both are optional and omitted when absent.
pub fn build_open(
    user: &str,
    ctp: &[u8; 16],
    mtu: u16,
    enc: u8,
    pipe: Option<(u16, u16)>,
    srlink: Option<u32>,
    nonce: u32,
) -> Vec<u8> {
    let mut pl = Vec::new();
    pl.extend(protocol::tlv(protocol::T_MTU, &mtu.to_be_bytes()));
    pl.extend(protocol::tlv(protocol::T_USERNAME, user.as_bytes()));
    pl.extend(protocol::tlv(protocol::T_PASSWORD, ctp));
    pl.extend(protocol::tlv(protocol::T_ENCRYPT, &[enc]));
    pl.extend(protocol::tlv(protocol::T_AUTH_VERIFY, &nonce.to_be_bytes()));
    if let Some((pipeidx, pipeid)) = pipe {
        let packed = (pipeidx << 15) | pipeid;
        pl.extend(protocol::tlv(protocol::T_PIPE, &packed.to_be_bytes()));
    }
    if let Some(link) = srlink {
        pl.extend(protocol::tlv(protocol::T_PIPE, &link.to_be_bytes()));
    }
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
        let mut message = String::from_utf8_lossy(&buf[24..]).to_string();
        for (typ, value) in protocol::parse_tlvs(&buf[24..]) {
            if typ == protocol::T_ERR_MSG {
                message = String::from_utf8_lossy(&value).to_string();
            }
        }
        let (code, reason) = auth_error(&message);
        anyhow::bail!("OPEN_REJECT code={code}: {reason} ({message})");
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
    let mut dns2 = None;
    let mut mtu: u16 = 1400;
    let mut enc = None;
    let mut ipv6 = None;
    let mut dns6 = None;
    let mut gw6 = None;
    let mut duppkt = None;
    let mut auth_verify = None;
    for (tt, v) in protocol::parse_tlvs(&buf[24..]) {
        match tt {
            protocol::T_IP if v.len() >= 4 => tun = protocol::ip_to_string(&v),
            protocol::T_GATEWAY if v.len() >= 4 => gw = protocol::ip_to_string(&v),
            protocol::T_DNS if v.len() >= 4 => {
                dns = protocol::ip_to_string(&v);
                if v.len() >= 8 {
                    dns2 = Some(protocol::ip_to_string(&v[4..]));
                }
            }
            protocol::T_MTU if v.len() >= 2 => mtu = u16::from_be_bytes([v[0], v[1]]),
            protocol::T_ENCRYPT if !v.is_empty() => enc = Some(v[0]),
            protocol::T_DUPPKT if !v.is_empty() => duppkt = Some(v[0]),
            protocol::T_AUTH_VERIFY => {
                if v.len() != 4 {
                    anyhow::bail!("AUTH_VERIFY wrong length {}", v.len());
                }
                let echo = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                if echo != expect_nonce {
                    anyhow::bail!(
                        "AUTH_VERIFY mismatch: got {echo:08x}, expected {expect_nonce:08x}"
                    );
                }
                auth_verify = Some(echo);
            }
            protocol::T_IPV6 if v.len() >= 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&v[..16]);
                ipv6 = Some(Ipv6Addr::from(a));
            }
            protocol::T_DNS6 if v.len() >= 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&v[..16]);
                dns6 = Some(Ipv6Addr::from(a));
            }
            protocol::T_GATEWAY6 if v.len() >= 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&v[..16]);
                gw6 = Some(Ipv6Addr::from(a));
            }
            _ => {}
        }
    }
    if !(576..=9000).contains(&mtu) {
        mtu = 1400;
    }
    Ok(AuthResult {
        sid,
        tok,
        tun,
        gw,
        dns,
        dns2,
        mtu,
        enc,
        ipv6,
        dns6,
        gw6,
        duppkt,
        auth_verify,
    })
}

pub fn ping_server(host: &str, port: u16, timeout_ms: u64, bind: Option<&str>) -> Result<Duration> {
    let sock = udp_connect(host, port, timeout_ms, bind)?;
    let header = protocol::pkhdr(protocol::PT_PING_REQ, 0, 0xFFFF, u32::MAX);
    let packet = protocol::ctrl_pkt(&header, &[]);
    let started = std::time::Instant::now();
    sock.send(&packet).context("send PING")?;
    let mut buf = [0u8; 64];
    let n = sock.recv(&mut buf).context("PING timeout")?;
    if n != 24
        || buf[0] != protocol::PT_PING_RSP
        || u16::from_be_bytes([buf[2], buf[3]]) != 0xFFFF
        || u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != u32::MAX
        || !protocol::verify_sig(&buf[..n])
    {
        anyhow::bail!("invalid PING response");
    }
    Ok(started.elapsed())
}

/// Map the Panabit server's rejection text to its Android client error code.
pub fn auth_error(message: &str) -> (u16, &'static str) {
    let upper = message.to_ascii_uppercase();
    for (needle, code, reason) in [
        ("TOOLONG", 2100, "Username too long"),
        ("FREEIP", 2111, "No available IP in resource pool"),
        ("PPPOECLNT", 2108, "PPPoE client not found"),
        ("PPOECLNT", 2108, "PPPoE client not found"),
        ("CLNT", 2108, "PPPoE client not found"),
        ("PPPOE_INSTAL", 2112, "Server license limit"),
        ("PPOE_INSTAL", 2112, "Server license limit"),
        ("PPPOEINSTALL", 2112, "Server license limit"),
        ("PPOEINSTALL", 2112, "Server license limit"),
        ("FAIL", 2116, "PPPoE installation failed"),
        ("NAME", 2102, "Invalid username"),
        ("PASS", 2105, "Invalid password"),
        ("ABLED", 2103, "Account disabled"),
        ("PIRED", 2104, "Account expired"),
        ("FULL", 2115, "Resource pool full"),
        ("EMPTY", 2115, "Resource pool empty"),
        ("POOL", 2106, "Invalid resource pool"),
        ("NO_ENTRY", 2107, "Maximum access users reached"),
        ("ENTRY", 2107, "Maximum access users reached"),
        ("BIND", 2109, "IP binding failed"),
        ("NULL", 2110, "Invalid resource pool"),
        ("POLL", 2101, "Invalid resource pool"),
    ] {
        if upper.contains(needle) {
            return (code, reason);
        }
    }
    (2999, "Unknown authentication error")
}

pub fn rand_u32() -> u32 {
    rand::random()
}

pub fn udp_connect(
    host: &str,
    port: u16,
    timeout_ms: u64,
    bind: Option<&str>,
) -> Result<std::net::UdpSocket> {
    let endpoint = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let a: std::net::SocketAddr = endpoint.parse().context("invalid address")?;
    let s = if a.is_ipv6() {
        std::net::UdpSocket::bind("[::]:0").context("bind IPv6 UDP")?
    } else {
        let target = super::netif::resolve(bind)?;
        let s = std::net::UdpSocket::bind(target.addr)
            .with_context(|| format!("bind UDP on {target}"))?;
        if let Some(device) = &target.device {
            super::netif::pin_to_device(&s, device);
        }
        if target.device.is_some() || !target.addr.ip().is_unspecified() {
            eprintln!("  bind {target}");
        }
        s
    };
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

pub fn get_ct(user: &str, pass: &str, ct_pass_hex: Option<&str>, salt: &str) -> Result<[u8; 16]> {
    let Some(hex) = ct_pass_hex else {
        return Ok(crypto::encrypt_password_salted(pass, user, salt));
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
