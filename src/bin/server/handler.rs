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

pub struct SrFragment {
    parts: Vec<(u16, Vec<u8>)>,
    eop: Option<usize>,
    created: Instant,
}

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
    let typ = raw[0];
    let sid = u16::from_be_bytes([raw[2], raw[3]]);
    let token = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);

    if typ == protocol::PT_SEGRT {
        handle_sr_echo(raw, addr, ctx);
        return;
    }

    match typ {
        protocol::PT_OPEN => handle_open(raw, addr, ctx),
        protocol::PT_DATA
        | protocol::PT_DATA_ENC
        | protocol::PT_DATA_IPV6
        | protocol::PT_DATA_DUP
        | protocol::PT_DATA_ENC_DUP => {
            let session = {
                let sessions = ctx.sessions.lock().unwrap();
                sessions.get(&sid).and_then(|session| {
                    (session.token == token).then(|| {
                        (
                            session.xor_key.clone(),
                            session.aes_key.clone(),
                            session.enc,
                        )
                    })
                })
            };
            let Some((xor_key, aes_key, enc)) = session else {
                return;
            };
            let mut payload = raw[8..].to_vec();
            if typ == protocol::PT_DATA_ENC || typ == protocol::PT_DATA_ENC_DUP {
                match enc {
                    1 => crypto::xor(&mut payload, &xor_key),
                    2 => {
                        if crypto::aes_ecb_decrypt(&mut payload, &aes_key).is_err() {
                            return;
                        }
                    }
                    _ => {}
                }
            }
            trim_ip(&mut payload);
            if !payload.is_empty() {
                tun::tun_write(ctx.tun, &payload);
            }
            if iwan::core::util::debug_enabled() {
                eprintln!(
                    "[UDP→TUN] type=0x{typ:02x} sid={sid:#06x} enc={enc} len={}",
                    payload.len()
                );
            }
        }
        protocol::PT_IPFRAG | protocol::PT_IPFRAG_ALT => {
            handle_fragment(raw, sid, token, ctx);
        }
        protocol::PT_CLOSE => {
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
        protocol::PT_ECHO_REQ if protocol::verify_sig(raw) => {
            send_echo_response(ctx.sock, addr, raw)
        }
        protocol::PT_PING_REQ if protocol::verify_sig(raw) => {
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

    for (typ, value) in protocol::parse_tlvs(&raw[24..]) {
        match typ {
            protocol::T_USERNAME => user = String::from_utf8_lossy(&value).to_string(),
            protocol::T_PASSWORD if value.len() >= 16 => ct_pass.copy_from_slice(&value[..16]),
            protocol::T_MTU if value.len() >= 2 => mtu = u16::from_be_bytes([value[0], value[1]]),
            protocol::T_ENCRYPT if !value.is_empty() => enc = value[0],
            protocol::T_PIPE if value.len() == 2 => {
                pipe_raw = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            protocol::T_PIPE if value.len() >= 4 => {
                srlink = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            protocol::T_AUTH_VERIFY if value.len() >= 4 => {
                auth_verify = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            protocol::T_IPV6 if value.len() >= 16 => {
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
            created: Instant::now(),
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
        let sessions = ctx.sessions.lock().unwrap();
        let Some(session) = sessions.get(&sid) else {
            return;
        };
        if session.token != token {
            return;
        }
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
            if cipher.len() % 16 != 0 || cipher.len() < pad {
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
        handle_fragment(&inner, sid, token, ctx);
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
        let sessions = ctx.sessions.lock().unwrap();
        let Some(session) = sessions.get(&sid) else {
            return;
        };
        if session.token != token {
            return;
        }
        match session.enc {
            1 => crypto::xor(&mut payload, &session.xor_key),
            2 => {
                if crypto::aes_ecb_decrypt(&mut payload, &session.aes_key).is_err() {
                    return;
                }
            }
            _ => {}
        }
    }
    trim_ip(&mut payload);
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

fn handle_fragment(raw: &[u8], sid: u16, token: u32, ctx: &ServerContext<'_>) {
    if raw.len() < 16 {
        return;
    }
    {
        let sessions = ctx.sessions.lock().unwrap();
        let Some(session) = sessions.get(&sid) else {
            return;
        };
        if session.token != token {
            return;
        }
    }
    let id = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let dword = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let frag_off = (((dword >> 2) & 0x1fff) as usize) * 1;
    let frag_len = ((dword >> 15) & 0x7ff) as usize;
    let end = (16 + frag_len).min(raw.len());
    if end <= 16 {
        return;
    }
    let part = raw[16..end].to_vec();
    let now = Instant::now();
    let mut frags = ctx.fragments.lock().unwrap();
    let entry = frags.entry((sid, id)).or_insert_with(|| SrFragment {
        parts: Vec::new(),
        eop: None,
        created: now,
    });
    if entry.parts.iter().any(|(off, _)| *off as usize == frag_off) {
        return;
    }
    if dword & 1 != 0 {
        entry.eop = Some(frag_off + part.len());
    }
    entry.parts.push((frag_off as u16, part));
    if entry.parts.len() > 16 || now.duration_since(entry.created).as_secs() > 10 {
        frags.remove(&(sid, id));
        return;
    }
    entry.parts.sort_by_key(|(off, _)| *off);
    let mut out = Vec::new();
    for (off, data) in entry.parts.iter() {
        if *off as usize != out.len() {
            return;
        }
        out.extend_from_slice(data);
    }
    if entry.eop != Some(out.len()) {
        return;
    }
    if let Some(first) = out.first() {
        let version = first >> 4;
        let ok = match version {
            4 => out.len() >= 20,
            6 => out.len() >= 40,
            _ => false,
        };
        if ok {
            frags.remove(&(sid, id));
            drop(frags);
            tun::tun_write(ctx.tun, &out);
        }
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

pub fn handle_tun_downlink(ip_pkt: &mut [u8], ctx: &ServerContext<'_>) {
    if ip_pkt.is_empty() {
        return;
    }
    let version = ip_pkt[0] >> 4;
    let found = {
        let sessions = ctx.sessions.lock().unwrap();
        match version {
            4 if ip_pkt.len() >= 20 => {
                let dst = Ipv4Addr::new(ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19]);
                sessions
                    .values()
                    .find(|session| session.ip == dst)
                    .map(|session| {
                        (
                            session.sid,
                            session.token,
                            session.addr,
                            session.xor_key.clone(),
                            session.aes_key.clone(),
                            session.enc,
                            session.srlink,
                        )
                    })
            }
            6 if ip_pkt.len() >= 40 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(&ip_pkt[24..40]);
                let dst = Ipv6Addr::from(a);
                sessions
                    .values()
                    .find(|session| session.ipv6 == dst)
                    .map(|session| {
                        (
                            session.sid,
                            session.token,
                            session.addr,
                            session.xor_key.clone(),
                            session.aes_key.clone(),
                            session.enc,
                            session.srlink,
                        )
                    })
            }
            _ => None,
        }
    };
    let Some((sid, token, addr, xor_key, aes_key, enc, srlink)) = found else {
        return;
    };

    if let Some(sr) = ctx.sr {
        if sr.enabled() && srlink.is_some() {
            if ctx.fragment {
                send_sr_fragmented(ip_pkt, sid, token, addr, sr, ctx.sock);
            } else {
                send_sr_packet(
                    ip_pkt, sid, token, addr, &xor_key, &aes_key, enc, sr, ctx.sock,
                );
            }
            return;
        }
    }

    if ctx.fragment {
        send_fragmented(ip_pkt, sid, token, addr, ctx.sock);
        return;
    }

    match version {
        4 => {
            let mut payload = ip_pkt.to_vec();
            if enc != 0 {
                if let Err(e) = encrypt_ipv4(&mut payload, &xor_key, &aes_key, enc) {
                    eprintln!("data encrypt failed: {e}");
                    return;
                }
            }
            let typ = if enc == 0 {
                protocol::PT_DATA
            } else {
                protocol::PT_DATA_ENC
            };
            let header = protocol::pkhdr(typ, enc, sid, token);
            ctx.sock
                .send_to(&protocol::data_pkt(&header, &payload), addr)
                .ok();
        }
        6 => {
            // The current Linux client emits IPv6 as type 0x23 without
            // encrypting it; keep the same behavior on the downlink.
            let header = protocol::pkhdr(protocol::PT_DATA_IPV6, 0, sid, token);
            ctx.sock
                .send_to(&protocol::data_pkt(&header, ip_pkt), addr)
                .ok();
        }
        _ => {}
    }
}

fn encrypt_ipv4(
    payload: &mut Vec<u8>,
    xor_key: &[u8],
    aes_key: &[u8],
    enc: u8,
) -> Result<(), String> {
    match enc {
        0 => Ok(()),
        1 => {
            crypto::xor(payload, xor_key);
            Ok(())
        }
        2 => {
            let pad = (16 - payload.len() % 16) % 16;
            payload.resize(payload.len() + pad, 0);
            crypto::aes_ecb_encrypt(payload, aes_key)
        }
        n => Err(format!("unsupported encryption mode {n}")),
    }
}

fn trim_ip(packet: &mut Vec<u8>) {
    match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 4 => {
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total >= 20 && total <= packet.len() {
                packet.truncate(total);
            }
        }
        Some(6) if packet.len() >= 40 => {
            let payload = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            let total = 40 + payload;
            if total <= packet.len() {
                packet.truncate(total);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn send_sr_packet(
    ip_pkt: &[u8],
    sid: u16,
    token: u32,
    addr: SocketAddr,
    xor_key: &[u8],
    aes_key: &[u8],
    enc: u8,
    sr: &SrConfig,
    sock: &UdpSocket,
) {
    let version = ip_pkt[0] >> 4;
    let inner_type = match version {
        4 if enc == 0 => protocol::PT_DATA,
        4 => protocol::PT_DATA_ENC,
        6 => protocol::PT_DATA_IPV6,
        _ => return,
    };
    let mut payload = ip_pkt.to_vec();
    if version == 4 && enc != 0 {
        if let Err(e) = encrypt_ipv4(&mut payload, xor_key, aes_key, enc) {
            eprintln!("SR inner encrypt failed: {e}");
            return;
        }
    }
    let pad = if sr.mode == 0 {
        0
    } else {
        let pad = (16 - payload.len() % 16) % 16;
        payload.resize(payload.len() + pad, 0);
        if let Err(e) = sr.encrypt(&mut payload) {
            eprintln!("SR encrypt failed: {e}");
            return;
        }
        pad
    };

    let links = &sr.links;
    let linkcnt = links.len().min(6) as u8;
    let mut pkt = Vec::with_capacity(4 + 4 * links.len() + 8 + payload.len());
    pkt.push(protocol::PT_SEGRT);
    pkt.push(0); // nextid
    pkt.push(linkcnt);
    pkt.push(((pad as u8) << 3) | (sr.mode & 7));
    // Android parses wire links and reverses them back to forwardLinks.
    for link in links.iter().rev().take(6) {
        pkt.extend_from_slice(&link.to_be_bytes());
    }
    pkt.extend_from_slice(&protocol::pkhdr(inner_type, enc, sid, token));
    pkt.extend_from_slice(&payload);
    sock.send_to(&pkt, addr).ok();

    if iwan::core::util::debug_enabled() {
        eprintln!(
            "[SR] sid={sid:#06x} links={linkcnt} pad={pad} inner=0x{inner_type:02x} len={}",
            pkt.len()
        );
    }
}

fn send_fragmented(ip_pkt: &[u8], sid: u16, token: u32, addr: SocketAddr, sock: &UdpSocket) {
    if ip_pkt.len() < 2 {
        return;
    }
    let id: u32 = rand::random();
    let half = ip_pkt.len() / 2;
    let frag_type = if ip_pkt[0] >> 4 == 6 {
        protocol::PT_IPFRAG_ALT
    } else {
        protocol::PT_IPFRAG
    };
    let send = |chunk: &[u8], off: u16, flag: u16| {
        if chunk.len() > 0x7ff {
            return;
        }
        let header = protocol::pkhdr(frag_type, 0, sid, token);
        let mut pkt = Vec::with_capacity(16 + chunk.len());
        pkt.extend_from_slice(&header);
        pkt.extend_from_slice(&id.to_le_bytes());
        let word = (off << 2) | flag;
        let dword = (((chunk.len() as u32) & 0x7ff) << 15) | word as u32;
        pkt.extend_from_slice(&dword.to_le_bytes());
        pkt.extend_from_slice(chunk);
        sock.send_to(&pkt, addr).ok();
    };
    // The client's reassembly table stores the first fragment, then on the
    // second fragment with bit0 set copies first at 0 and second at off.
    send(&ip_pkt[..half], 0, 0);
    send(&ip_pkt[half..], half as u16, 1);
    if iwan::core::util::debug_enabled() {
        eprintln!("[FRAG] sid={sid:#06x} id={id:#010x} len={}", ip_pkt.len());
    }
}

#[allow(clippy::too_many_arguments)]
fn send_sr_fragmented(
    ip_pkt: &[u8],
    sid: u16,
    token: u32,
    addr: SocketAddr,
    sr: &SrConfig,
    sock: &UdpSocket,
) {
    // The client's onIPFRAG() performs the SR AES decrypt after reassembly
    // but does not apply the XOR layer to fragments. Keep this path AES-only.
    let mut ciphertext = ip_pkt.to_vec();
    let pad = if sr.mode == 0 {
        0
    } else {
        let pad = (16 - ciphertext.len() % 16) % 16;
        ciphertext.resize(ciphertext.len() + pad, 0);
        if let Err(e) = sr.encrypt(&mut ciphertext) {
            eprintln!("SR fragment encrypt failed: {e}");
            return;
        }
        pad
    };
    if ciphertext.len() < 2 {
        return;
    }
    let id: u32 = rand::random();
    let half = ciphertext.len() / 2;
    let links = &sr.links;
    let linkcnt = links.len().min(6) as u8;
    let flags = ((pad as u8) << 3) | (sr.mode & 7);
    let frag_type = if ip_pkt[0] >> 4 == 6 {
        protocol::PT_IPFRAG_ALT
    } else {
        protocol::PT_IPFRAG
    };
    let send = |chunk: &[u8], off: u16, frag_flag: u16| {
        let mut pkt = Vec::with_capacity(4 + 4 * links.len() + 16 + chunk.len());
        pkt.push(protocol::PT_SEGRT);
        pkt.push(0);
        pkt.push(linkcnt);
        pkt.push(flags);
        for link in links.iter().rev().take(6) {
            pkt.extend_from_slice(&link.to_be_bytes());
        }
        pkt.extend_from_slice(&protocol::pkhdr(frag_type, 0, sid, token));
        pkt.extend_from_slice(&id.to_le_bytes());
        let word = (off << 2) | frag_flag;
        let dword = (((chunk.len() as u32) & 0x7ff) << 15) | word as u32;
        pkt.extend_from_slice(&dword.to_le_bytes());
        pkt.extend_from_slice(chunk);
        sock.send_to(&pkt, addr).ok();
    };
    send(&ciphertext[..half], 0, 0);
    send(&ciphertext[half..], half as u16, 1);
    if iwan::core::util::debug_enabled() {
        eprintln!(
            "[SR+FRAG] sid={sid:#06x} id={id:#010x} len={} pad={pad}",
            ciphertext.len()
        );
    }
}
