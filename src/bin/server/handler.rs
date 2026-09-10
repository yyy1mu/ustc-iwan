use crate::session::Session;
use iwan::core::{crypto, protocol, tun};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub type SessionMap = Arc<Mutex<HashMap<u16, Session>>>;

pub struct ServerContext<'a> {
    pub users: &'a HashMap<String, String>,
    pub sessions: &'a SessionMap,
    pub next_ip: &'a AtomicU32,
    pub server_ip: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub sock: &'a UdpSocket,
    pub tun: RawFd,
}

pub fn handle_udp(raw: &[u8], addr: SocketAddr, ctx: &ServerContext<'_>) {
    if raw.len() < 8 {
        return;
    }
    let typ = raw[0];
    let sid = u16::from_be_bytes([raw[2], raw[3]]);

    match typ {
        protocol::PT_OPEN => handle_open(raw, addr, ctx),
        protocol::PT_DATA | protocol::PT_DATA_ENC => {
            let key = ctx
                .sessions
                .lock()
                .unwrap()
                .get(&sid)
                .map(|session| session.xor_key.clone());
            if let Some(key) = key {
                let mut payload = raw[8..].to_vec();
                if typ == protocol::PT_DATA_ENC {
                    crypto::xor(&mut payload, &key);
                }
                tun::tun_write(ctx.tun, &payload);
            }
        }
        protocol::PT_CLOSE => {
            let mut sessions = ctx.sessions.lock().unwrap();
            if let Some(session) = sessions.remove(&sid) {
                println!("[{addr:?}] session {sid:#06x} (ip {}) closed", session.ip);
            }
        }
        protocol::PT_PING_REQ if protocol::verify_sig(raw) => send_pong(ctx.sock, addr),
        protocol::PT_ECHO_REQ if protocol::verify_sig(raw) => {
            send_echo_response(ctx.sock, addr, raw)
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
    for (typ, value) in protocol::parse_tlvs(&raw[24..]) {
        match typ {
            protocol::T_USERNAME => user = String::from_utf8_lossy(&value).to_string(),
            protocol::T_PASSWORD if value.len() >= 16 => ct_pass.copy_from_slice(&value[..16]),
            protocol::T_MTU if value.len() >= 2 => mtu = u16::from_be_bytes([value[0], value[1]]),
            protocol::T_ENCRYPT if !value.is_empty() => enc = value[0],
            _ => {}
        }
    }

    let Some(pass_plain) = ctx.users.get(&user).cloned() else {
        println!("[{addr:?}] OPEN reject: unknown user {user}");
        send_reject(ctx.sock, addr, "unknown user");
        return;
    };
    if ct_pass != crypto::encrypt_password(&pass_plain, &user) {
        println!("[{addr:?}] OPEN reject: bad password for {user}");
        send_reject(ctx.sock, addr, "bad password");
        return;
    }

    let client_ip = Ipv4Addr::from(ctx.next_ip.fetch_add(1, Ordering::Relaxed));
    let sid = (u32::from(client_ip) & 0xFFFF) as u16;
    let token: u32 = rand::random();

    let mut payload = Vec::new();
    payload.extend(protocol::tlv(protocol::T_MTU, &mtu.to_be_bytes()));
    payload.extend(protocol::tlv(protocol::T_IP, &client_ip.octets()));
    payload.extend(protocol::tlv(protocol::T_GATEWAY, &ctx.server_ip.octets()));
    payload.extend(protocol::tlv(protocol::T_DNS, &ctx.dns.octets()));
    payload.extend(protocol::tlv(protocol::T_ENCRYPT, &[enc]));

    let header = protocol::pkhdr(protocol::PT_OPEN_ACK, enc, sid, token);
    ctx.sock
        .send_to(&protocol::ctrl_pkt(&header, &payload), addr)
        .ok();
    println!("[{addr:?}] OPEN_ACK → {user} sid={sid:#06x} ip={client_ip} enc={enc}");

    let session_key = crypto::session_key(&user, &pass_plain);
    let mut sessions = ctx.sessions.lock().unwrap();
    sessions.insert(
        sid,
        Session {
            sid,
            token,
            addr,
            ip: client_ip,
            xor_key: session_key[..8].to_vec(),
            enc,
            created: Instant::now(),
        },
    );
}

fn send_reject(sock: &UdpSocket, addr: SocketAddr, msg: &str) {
    let header = protocol::pkhdr(protocol::PT_OPEN_REJECT, 0, 0, 0);
    let body = protocol::tlv(protocol::T_ERR_MSG, msg.as_bytes());
    sock.send_to(&protocol::ctrl_pkt(&header, &body), addr).ok();
}

fn send_pong(sock: &UdpSocket, addr: SocketAddr) {
    let header = protocol::pkhdr(protocol::PT_PING_RSP, 0, 0xFFFF, 0xFFFF_FFFF);
    sock.send_to(&protocol::ctrl_pkt(&header, &[]), addr).ok();
}

fn send_echo_response(sock: &UdpSocket, addr: SocketAddr, raw: &[u8]) {
    let sid = u16::from_be_bytes([raw[2], raw[3]]);
    let token = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let header = protocol::pkhdr(protocol::PT_ECHO_RES, raw[1], sid, token);
    sock.send_to(&protocol::ctrl_pkt(&header, &[]), addr).ok();
}

pub fn handle_tun_downlink(ip_pkt: &mut [u8], sessions: &SessionMap, sock: &UdpSocket) {
    if ip_pkt.len() < 20 {
        return;
    }
    let dst = Ipv4Addr::new(ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19]);
    let found = {
        let sessions = sessions.lock().unwrap();
        sessions
            .values()
            .find(|session| session.ip == dst)
            .map(|session| {
                (
                    session.sid,
                    session.token,
                    session.addr,
                    session.xor_key.clone(),
                    session.enc,
                )
            })
    };
    let Some((sid, token, addr, xor_key, enc)) = found else {
        return;
    };

    let mut payload = ip_pkt.to_vec();
    crypto::xor(&mut payload, &xor_key);
    let header = protocol::pkhdr(protocol::PT_DATA_ENC, enc, sid, token);
    sock.send_to(&protocol::data_pkt(&header, &payload), addr)
        .ok();
}
