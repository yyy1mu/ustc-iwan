use crate::fragment::SrFragment;
use crate::session::Session;
use iwan::core::sr::SrConfig;
use iwan::core::{crypto, protocol, tun};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub type SessionMap = Arc<Mutex<HashMap<u16, Session>>>;

pub struct ServerContext<'a> {
    pub users: &'a HashMap<String, String>,
    pub sessions: &'a SessionMap,
    pub fragments: &'a Mutex<HashMap<(u16, u32), SrFragment>>,
    pub next_ip: &'a AtomicU32,
    pub next_ipv6: &'a AtomicU32,
    pub server_ip: Ipv4Addr,
    pub server_ipv6: Ipv6Addr,
    pub dns: Ipv4Addr,
    pub dns2: Ipv4Addr,
    pub dns_ipv6: Ipv6Addr,
    pub sr: Option<&'a SrConfig>,
    pub fragment: bool,
    pub salt: &'a str,
    pub duppkt: u8,
    pub sock: &'a UdpSocket,
    pub tun: RawFd,
}

pub fn handle_udp(raw: &[u8], addr: SocketAddr, ctx: &ServerContext<'_>) {
    if raw.len() < 8 {
        return;
    }
    let raw_type = raw[0];
    let Some(typ) = protocol::PacketType::from_u8(raw_type) else {
        return;
    };
    let sid = u16::from_be_bytes([raw[2], raw[3]]);
    let token = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);

    if typ == protocol::PacketType::SegmentRouting {
        handle_sr_echo(raw, addr, ctx);
        return;
    }

    match typ {
        protocol::PacketType::Open => handle_open(raw, addr, ctx),
        protocol::PacketType::Data
        | protocol::PacketType::DataEncrypted
        | protocol::PacketType::DataIpv6
        | protocol::PacketType::DataDup
        | protocol::PacketType::DataEncDup => {
            let session = {
                let mut sessions = ctx.sessions.lock().unwrap();
                let Some(session) = sessions.get_mut(&sid) else {
                    return;
                };
                if session.token != token {
                    return;
                }
                session.last_seen = Instant::now();
                (
                    session.xor_key.clone(),
                    session.aes_key.clone(),
                    session.enc,
                )
            };
            let (xor_key, aes_key, enc) = session;
            let mut payload = raw[8..].to_vec();
            if raw_type == protocol::PT_DATA_ENC || raw_type == protocol::PT_DATA_ENC_DUP {
                match enc {
                    1 => crypto::xor(&mut payload, &xor_key),
                    2 if crypto::aes_ecb_decrypt(&mut payload, &aes_key).is_err() => return,
                    2 => {}
                    _ => {}
                }
            }
            crate::downlink::trim_ip(&mut payload);
            if !payload.is_empty() {
                tun::tun_write(ctx.tun, &payload);
            }
            if iwan::core::util::debug_enabled() {
                eprintln!(
                    "[UDP→TUN] type=0x{raw_type:02x} sid={sid:#06x} enc={enc} len={}",
                    payload.len()
                );
            }
        }
        protocol::PacketType::IpFragment | protocol::PacketType::IpFragmentIpv6 => {
            crate::fragment::handle_fragment(raw, sid, token, ctx);
        }
        protocol::PacketType::Close => {
            let mut sessions = ctx.sessions.lock().unwrap();
            if let Some(session) = sessions.get(&sid) {
                if session.token != token {
                    return;
                }
            }
            if let Some(session) = sessions.remove(&sid) {
                println!("[{addr:?}] session {sid:#06x} (ip {}) closed", session.ip);
            }
        }
        protocol::PacketType::EchoRequest if protocol::verify_sig(raw) => {
            touch_session(ctx, sid, token);
            send_echo_response(ctx.sock, addr, raw)
        }
        protocol::PacketType::PingRequest if protocol::verify_sig(raw) => {
            let header = protocol::pkhdr(protocol::PT_PING_RSP, 0, 0xFFFF, 0xFFFF_FFFF);
            ctx.sock
                .send_to(&protocol::ctrl_pkt(&header, &[]), addr)
                .ok();
        }
        _ => {}
    }
}

fn handle_open(raw: &[u8], addr: SocketAddr, ctx: &ServerContext<'_>) {
    if raw.len() < 24 || !protocol::verify_sig(raw) {
        return;
    }

    let mut user = String::new();
    let mut ct_pass = [0u8; 16];
    let mut mtu: u16 = 1400;
    let mut enc = 0u8;
    let mut pipe_raw: Option<u16> = None;
    let mut srlink: Option<u32> = None;
    let mut auth_verify: Option<u32> = None;
    let mut client_ipv6: Option<Ipv6Addr> = None;

    for tlv in protocol::parse_tlvs(&raw[24..]) {
        let value = &tlv.value;
        match tlv.typ {
            protocol::TlvType::Username => user = String::from_utf8_lossy(value).to_string(),
            protocol::TlvType::Password if value.len() >= 16 => {
                ct_pass.copy_from_slice(&value[..16])
            }
            protocol::TlvType::Mtu if value.len() >= 2 => {
                mtu = u16::from_be_bytes([value[0], value[1]])
            }
            protocol::TlvType::Encrypt if !value.is_empty() => enc = value[0],
            protocol::TlvType::Link if value.len() == 2 => {
                pipe_raw = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            protocol::TlvType::Link if value.len() >= 4 => {
                srlink = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            protocol::TlvType::AuthVerify if value.len() >= 4 => {
                auth_verify = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            protocol::TlvType::Ip6 if value.len() >= 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&value[..16]);
                client_ipv6 = Some(Ipv6Addr::from(a));
            }
            _ => {}
        }
    }

    if enc > 2 {
        println!("[{addr:?}] OPEN reject: unsupported encrypt mode {enc}");
        send_reject(ctx.sock, addr, "unsupported encrypt mode");
        return;
    }
    if !(576..=9000).contains(&mtu) {
        eprintln!("[{addr:?}] OPEN MTU {mtu} out of range, using 1400");
        mtu = 1400;
    }

    let Some(pass_plain) = ctx.users.get(&user).cloned() else {
        println!("[{addr:?}] OPEN reject: unknown user {user}");
        send_reject(ctx.sock, addr, "unknown user");
        return;
    };
    if ct_pass != crypto::encrypt_password_salted(&pass_plain, &user, ctx.salt) {
        println!("[{addr:?}] OPEN reject: bad password for {user}");
        send_reject(ctx.sock, addr, "bad password");
        return;
    }

    let client_ip = Ipv4Addr::from(ctx.next_ip.fetch_add(1, Ordering::Relaxed));
    let suffix = ctx.next_ipv6.fetch_add(1, Ordering::Relaxed) as u128;
    let assigned_ipv6 =
        client_ipv6.unwrap_or_else(|| Ipv6Addr::from(u128::from(ctx.server_ipv6) + suffix));
    let sid = (u32::from(client_ip) & 0xFFFF) as u16;
    let token: u32 = rand::random();
    let pipeid = pipe_raw.map(|p| p & 0x7fff);
    let pipeidx = pipe_raw.map(|p| p >> 15);

    // The current Linux client requires two IPv4 DNS addresses in T_DNS.
    let mut dns_pair = Vec::with_capacity(8);
    dns_pair.extend_from_slice(&ctx.dns.octets());
    dns_pair.extend_from_slice(&ctx.dns2.octets());

    let mut payload = Vec::new();
    payload.extend(protocol::tlv(protocol::T_MTU, &mtu.to_be_bytes()));
    payload.extend(protocol::tlv(protocol::T_IP, &client_ip.octets()));
    payload.extend(protocol::tlv(protocol::T_GATEWAY, &ctx.server_ip.octets()));
    payload.extend(protocol::tlv(protocol::T_DNS, &dns_pair));
    payload.extend(protocol::tlv(protocol::T_ENCRYPT, &[enc]));
    payload.extend(protocol::tlv(protocol::T_DUPPKT, &[ctx.duppkt]));
    payload.extend(protocol::tlv(protocol::T_IPV6, &assigned_ipv6.octets()));
    payload.extend(protocol::tlv(protocol::T_DNS6, &ctx.dns_ipv6.octets()));
    payload.extend(protocol::tlv(
        protocol::T_GATEWAY6,
        &ctx.server_ipv6.octets(),
    ));
    if let Some(nonce) = auth_verify {
        payload.extend(protocol::tlv(protocol::T_AUTH_VERIFY, &nonce.to_be_bytes()));
    }

    let header = protocol::pkhdr(protocol::PT_OPEN_ACK, enc, sid, token);
    ctx.sock
        .send_to(&protocol::ctrl_pkt(&header, &payload), addr)
        .ok();
    println!(
        "[{addr:?}] OPEN_ACK → {user} sid={sid:#06x} ip={client_ip} ip6={assigned_ipv6} \
         mtu={mtu} enc={enc} pipeid={pipeid:?} pipeidx={pipeidx:?} srlink={srlink:?} \
         auth_verify={auth_verify:?}"
    );

    let session_key = crypto::session_key(&user, &pass_plain);
    let mut sessions = ctx.sessions.lock().unwrap();
    sessions.insert(
        sid,
        Session {
            sid,
            token,
            addr,
            ip: client_ip,
            ipv6: assigned_ipv6,
            xor_key: session_key[..8].to_vec(),
            aes_key: session_key.to_vec(),
            enc,
            pipeid,
            pipeidx,
            srlink,
            last_seen: Instant::now(),
        },
    );
}

fn handle_sr_echo(raw: &[u8], addr: SocketAddr, ctx: &ServerContext<'_>) {
    if raw.len() < 8 {
        return;
    }
    let linkcnt = raw[2] as usize;
    let srheader_len = 4 * linkcnt + 4;
    if linkcnt == 0 || raw.len() < srheader_len + 8 {
        return;
    }
    let flags = raw[3];
    let inner_type = raw[srheader_len];
    let mut inner = raw[srheader_len..].to_vec();
    let sid = u16::from_be_bytes([inner[2], inner[3]]);
    let token = u32::from_be_bytes([inner[4], inner[5], inner[6], inner[7]]);
    {
        let mut sessions = ctx.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(&sid) else {
            return;
        };
        if session.token != token {
            return;
        }
        session.last_seen = Instant::now();
    }

    if inner_type == protocol::PT_ECHO_REQ {
        let mut reply = raw[..srheader_len].to_vec();
        reply[1] = 0; // endpoint/terminal SR header
        reply.extend_from_slice(&protocol::pkhdr(protocol::PT_ECHO_RES, 0, sid, token));
        reply.extend_from_slice(&inner[8..]);
        ctx.sock.send_to(&reply, addr).ok();
        if iwan::core::util::debug_enabled() {
            eprintln!("[SR-ECHO] sid={sid:#06x} len={}", reply.len());
        }
        return;
    }

    // Android profile B: SR outer AES. Decrypt before inner handling.
    if let Some(sr) = ctx.sr {
        let algo = flags & 7;
        if algo != 0 && algo == sr.mode {
            let pad = (flags >> 3) as usize;
            let mut cipher = inner[8..].to_vec();
            if !cipher.len().is_multiple_of(16) || cipher.len() < pad {
                return;
            }
            if sr.decrypt(&mut cipher).is_err() {
                return;
            }
            cipher.truncate(cipher.len() - pad);
            inner.truncate(8);
            inner.extend_from_slice(&cipher);
        }
    }

    let typ = inner[0];
    if typ == protocol::PT_IPFRAG || typ == protocol::PT_IPFRAG_ALT {
        crate::fragment::handle_fragment(&inner, sid, token, ctx);
        return;
    }
    if typ != protocol::PT_DATA
        && typ != protocol::PT_DATA_ENC
        && typ != protocol::PT_DATA_IPV6
        && typ != protocol::PT_DATA_DUP
        && typ != protocol::PT_DATA_ENC_DUP
    {
        return;
    }
    let mut payload = inner[8..].to_vec();
    if typ == protocol::PT_DATA_ENC || typ == protocol::PT_DATA_ENC_DUP {
        let mut sessions = ctx.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(&sid) else {
            return;
        };
        if session.token != token {
            return;
        }
        session.last_seen = Instant::now();
        match session.enc {
            1 => crypto::xor(&mut payload, &session.xor_key),
            2 if crypto::aes_ecb_decrypt(&mut payload, &session.aes_key).is_err() => return,
            2 => {}
            _ => {}
        }
    }
    crate::downlink::trim_ip(&mut payload);
    if !payload.is_empty() {
        tun::tun_write(ctx.tun, &payload);
    }
    if iwan::core::util::debug_enabled() {
        eprintln!(
            "[SR-DATA] sid={sid:#06x} flags=0x{flags:02x} inner=0x{typ:02x} len={}",
            payload.len()
        );
    }
}

fn touch_session(ctx: &ServerContext<'_>, sid: u16, token: u32) {
    let mut sessions = ctx.sessions.lock().unwrap();
    if let Some(session) = sessions.get_mut(&sid) {
        if session.token == token {
            session.last_seen = Instant::now();
        }
    }
}

pub fn reap_sessions(sessions: &SessionMap, idle: std::time::Duration) {
    let mut sessions = sessions.lock().unwrap();
    let before = sessions.len();
    sessions.retain(|_, session| session.last_seen.elapsed() < idle);
    let removed = before.saturating_sub(sessions.len());
    if removed > 0 {
        println!("reaped {removed} idle session(s)");
    }
}

fn send_reject(sock: &UdpSocket, addr: SocketAddr, msg: &str) {
    let header = protocol::pkhdr(protocol::PT_OPEN_REJECT, 0, 0, 0);
    let body = protocol::tlv(protocol::T_ERR_MSG, msg.as_bytes());
    sock.send_to(&protocol::ctrl_pkt(&header, &body), addr).ok();
}

fn send_echo_response(sock: &UdpSocket, addr: SocketAddr, raw: &[u8]) {
    let sid = u16::from_be_bytes([raw[2], raw[3]]);
    let token = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let header = protocol::pkhdr(protocol::PT_ECHO_RES, raw[1], sid, token);
    let payload = raw.get(24..).unwrap_or(&[]);
    sock.send_to(&protocol::ctrl_pkt(&header, payload), addr)
        .ok();
}
