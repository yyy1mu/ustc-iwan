use crate::session::Session;
use iwan::core::{crypto, protocol, tun};
use std::collections::HashMap;
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub type SessionMap = Arc<Mutex<HashMap<u16, Session>>>;

pub fn handle_udp(
    raw: &[u8],
    addr: SocketAddr,
    users: &HashMap<String, String>,
    sessions: &SessionMap,
    next_ip: &Arc<Mutex<u32>>,
    server_ip: &str,
    dns: &str,
    sock: &UdpSocket,
    tun: RawFd,
) {
    if raw.len() < 8 {
        return;
    }
    let typ = raw[0];
    let sid = u16::from_be_bytes([raw[2], raw[3]]);

    match typ {
        protocol::PT_OPEN => handle_open(raw, addr, users, sessions, next_ip, server_ip, dns, sock),
        protocol::PT_DATA | protocol::PT_DATA_ENC => {
            let s = sessions.lock().unwrap();
            if let Some(ses) = s.get(&sid) {
                let key = ses.xor_key.clone();
                drop(s);
                let mut payload = raw[8..].to_vec();
                if typ == protocol::PT_DATA_ENC {
                    crypto::xor(&mut payload, &key);
                }
                tun::tun_write(tun, &payload);
            }
        }
        protocol::PT_CLOSE => {
            let mut s = sessions.lock().unwrap();
            if let Some(ses) = s.remove(&sid) {
                println!("[{addr:?}] session {sid:#06x} (ip {}) closed", ses.ip);
            }
        }
        protocol::PT_PING_REQ => {
            if protocol::verify_sig(raw) {
                send_pong(sock, addr);
            }
        }
        protocol::PT_ECHO_REQ => {
            if protocol::verify_sig(raw) {
                send_echo_response(sock, addr, raw);
            }
        }
        _ => {}
    }
}

fn handle_open(
    raw: &[u8],
    addr: SocketAddr,
    users: &HashMap<String, String>,
    sessions: &SessionMap,
    next_ip: &Arc<Mutex<u32>>,
    server_ip: &str,
    dns: &str,
    sock: &UdpSocket,
) {
    if raw.len() < 24 || !protocol::verify_sig(raw) {
        return;
    }
    let tlvs = protocol::parse_tlvs(&raw[24..]);

    let mut user = String::new();
    let mut ct_pass = [0u8; 16];
    let mut mtu: u16 = 1400;
    let mut enc = 0u8;
    for (t, v) in &tlvs {
        match *t {
            protocol::T_USERNAME => user = String::from_utf8_lossy(v).to_string(),
            protocol::T_PASSWORD if v.len() >= 16 => ct_pass.copy_from_slice(&v[..16]),
            protocol::T_MTU if v.len() >= 2 => mtu = u16::from_be_bytes([v[0], v[1]]),
            protocol::T_ENCRYPT if !v.is_empty() => enc = v[0],
            _ => {}
        }
    }

    let pass_plain = match users.get(&user) {
        Some(p) => p.clone(),
        None => {
            println!("[{addr:?}] OPEN reject: unknown user {user}");
            send_reject(sock, addr, "unknown user");
            return;
        }
    };
    if ct_pass != crypto::encrypt_password(&pass_plain, &user) {
        println!("[{addr:?}] OPEN reject: bad password for {user}");
        send_reject(sock, addr, "bad password");
        return;
    }

    let mut nip = next_ip.lock().unwrap();
    let client_ip_u32 = *nip;
    *nip += 1;
    drop(nip);
    let client_ip = ip_from_u32(client_ip_u32);
    let new_sid = (client_ip_u32 & 0xFFFF) as u16;
    let token = rand_u32().unwrap_or(0);

    let sk = crypto::session_key(&user, &pass_plain);
    let mut pl = Vec::new();
    pl.extend(protocol::tlv(protocol::T_MTU, &mtu.to_be_bytes()));
    pl.extend(protocol::tlv(protocol::T_IP, &protocol::s2ip4(&client_ip)));
    pl.extend(protocol::tlv(
        protocol::T_GATEWAY,
        &protocol::s2ip4(server_ip),
    ));
    pl.extend(protocol::tlv(protocol::T_DNS, &protocol::s2ip4(dns)));
    pl.extend(protocol::tlv(protocol::T_ENCRYPT, &[enc]));

    let h = protocol::pkhdr(protocol::PT_OPEN_ACK, enc, new_sid, token);
    sock.send_to(&protocol::ctrl_pkt(&h, &pl), addr).ok();
    println!("[{addr:?}] OPEN_ACK → {user} sid={new_sid:#06x} ip={client_ip} enc={enc}");

    let mut s = sessions.lock().unwrap();
    s.remove(&new_sid);
    s.insert(
        new_sid,
        Session {
            sid: new_sid,
            token,
            addr,
            ip: client_ip.clone(),
            ip_bytes: protocol::s2ip4(&client_ip),
            xor_key: sk[..8].to_vec(),
            enc,
            created: Instant::now(),
        },
    );
}

fn send_reject(sock: &UdpSocket, addr: SocketAddr, msg: &str) {
    let h = protocol::pkhdr(protocol::PT_OPEN_REJECT, 0, 0, 0);
    let body = protocol::tlv(protocol::T_ERR_MSG, msg.as_bytes());
    sock.send_to(&protocol::ctrl_pkt(&h, &body), addr).ok();
}

fn send_pong(sock: &UdpSocket, addr: SocketAddr) {
    let h = protocol::pkhdr(protocol::PT_PING_RSP, 0, 0xFFFF, 0xFFFF_FFFF);
    sock.send_to(&protocol::ctrl_pkt(&h, &[]), addr).ok();
}

fn send_echo_response(sock: &UdpSocket, addr: SocketAddr, raw: &[u8]) {
    let sid = u16::from_be_bytes([raw[2], raw[3]]);
    let token = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let h = protocol::pkhdr(protocol::PT_ECHO_RES, raw[1], sid, token);
    sock.send_to(&protocol::ctrl_pkt(&h, &[]), addr).ok();
}

pub fn handle_tun_downlink(ip_pkt: &mut [u8], sessions: &SessionMap, sock: &UdpSocket) {
    if ip_pkt.len() < 20 {
        return;
    }
    let dst = [ip_pkt[16], ip_pkt[17], ip_pkt[18], ip_pkt[19]];
    let s = sessions.lock().unwrap();
    let mut found: Option<(u16, u32, SocketAddr, Vec<u8>, u8)> = None;
    for (_, ses) in s.iter() {
        if ses.ip_bytes == dst {
            found = Some((ses.sid, ses.token, ses.addr, ses.xor_key.clone(), ses.enc));
            break;
        }
    }
    drop(s);
    if let Some((sid, token, addr, xk, enc)) = found {
        let mut payload = ip_pkt.to_vec();
        crypto::xor(&mut payload, &xk);
        let h = protocol::pkhdr(protocol::PT_DATA_ENC, enc, sid, token);
        sock.send_to(&protocol::data_pkt(&h, &payload), addr).ok();
    }
}

fn ip_from_u32(u: u32) -> String {
    let b = u.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn rand_u32() -> Result<u32, std::io::Error> {
    let mut b = [0u8; 4];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
