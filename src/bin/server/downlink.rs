//! Server-to-client data-plane encoding.

use crate::handler::ServerContext;
use iwan::core::sr::SrConfig;
use iwan::core::{crypto, protocol};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub fn handle(ip_pkt: &mut [u8], ctx: &ServerContext<'_>) {
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

pub fn trim_ip(packet: &mut Vec<u8>) {
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
