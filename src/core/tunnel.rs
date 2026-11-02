use crate::core::{crypto, protocol, sr::SrConfig};
use anyhow::{bail, Result};
use std::collections::HashMap;

/// Maximum number of concurrent fragment IDs retained by the client.
const MAX_FRAGMENTS: usize = 16;

struct FragEntry {
    parts: Vec<(u16, Vec<u8>)>,
    sr: Option<SrConfig>,
    sr_pad: Option<u8>,
}

/// Downlink packet processor for the new protocol: IPv4/IPv6 DATA,
/// 0x22/0x24 fragments, and 0x28 SEGRT/SR.
pub struct TunnelRx {
    xor_key: Vec<u8>,
    aes_key: Vec<u8>,
    enc: u8,
    sid: u16,
    token: u32,
    sr: Option<SrConfig>,
    frags: HashMap<u32, FragEntry>,
}

impl TunnelRx {
    pub fn new(
        xor_key: &[u8],
        aes_key: &[u8],
        enc: u8,
        sid: u16,
        token: u32,
        sr: Option<SrConfig>,
    ) -> Self {
        Self {
            xor_key: xor_key.to_vec(),
            aes_key: aes_key.to_vec(),
            enc,
            sid,
            token,
            sr,
            frags: HashMap::new(),
        }
    }

    pub fn handle(&mut self, buf: &[u8], emit: &mut dyn FnMut(&[u8])) -> Result<()> {
        if buf.len() < 8 {
            return Ok(());
        }
        if buf[0] == protocol::PT_SEGRT {
            self.handle_sr(buf, emit)
        } else {
            self.handle_inner(buf, 0, None, emit)
        }
    }

    fn handle_sr(&mut self, buf: &[u8], emit: &mut dyn FnMut(&[u8])) -> Result<()> {
        if buf.len() < 8 {
            return Ok(());
        }
        let linkcnt = buf[2] as usize;
        let srheader_len = 4 * linkcnt + 4;
        if buf.len() < srheader_len + 8 {
            return Ok(());
        }
        let flags = buf[3];
        let algo = flags & 7;
        let pad = flags >> 3;
        let Some(sr) = self.sr.clone() else {
            return Ok(());
        };
        if algo != (sr.mode & 7) {
            return Ok(());
        }
        let inner_type = buf[srheader_len];
        if inner_type == protocol::PT_IPFRAG || inner_type == protocol::PT_IPFRAG_ALT {
            // Server encrypts the whole packet before splitting it, so the
            // fragments are ciphertext; decrypt after reassembly.
            return self.handle_inner(buf, srheader_len, Some((sr, pad)), emit);
        }

        let mut cipher = buf[srheader_len + 8..].to_vec();
        let pad = if sr.mode == 0 {
            0
        } else {
            if cipher.is_empty() || !cipher.len().is_multiple_of(16) {
                return Ok(());
            }
            sr.decrypt(&mut cipher)
                .map_err(|e| anyhow::anyhow!("SR decrypt: {e}"))?;
            pad as usize
        };
        if cipher.len() < pad {
            return Ok(());
        }
        cipher.truncate(cipher.len() - pad);
        let mut inner = buf[srheader_len..srheader_len + 8].to_vec();
        inner.extend_from_slice(&cipher);
        self.handle_inner(&inner, 0, None, emit)
    }

    fn handle_inner(
        &mut self,
        buf: &[u8],
        off: usize,
        sr_ctx: Option<(SrConfig, u8)>,
        emit: &mut dyn FnMut(&[u8]),
    ) -> Result<()> {
        if buf.len() < off + 8 {
            return Ok(());
        }
        let typ = buf[off];
        let sid = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let token = u32::from_be_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        if sid != self.sid || token != self.token {
            return Ok(());
        }

        match typ {
            protocol::PT_DATA
            | protocol::PT_DATA_ENC
            | protocol::PT_DATA_IPV6
            | protocol::PT_DATA_DUP
            | protocol::PT_DATA_ENC_DUP => {
                let mut payload = buf[off + 8..].to_vec();
                if typ == protocol::PT_DATA_ENC || typ == protocol::PT_DATA_ENC_DUP {
                    match self.enc {
                        1 => crypto::xor(&mut payload, &self.xor_key),
                        2 => crypto::aes_ecb_decrypt(&mut payload, &self.aes_key)
                            .map_err(|e| anyhow::anyhow!("AES decrypt: {e}"))?,
                        _ => {}
                    }
                }
                if is_ip(&payload) {
                    trim_ip(&mut payload);
                    emit(&payload);
                }
            }
            protocol::PT_IPFRAG | protocol::PT_IPFRAG_ALT => {
                if buf.len() < off + 16 {
                    return Ok(());
                }
                let id =
                    u32::from_le_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]);
                let dword = u32::from_le_bytes([
                    buf[off + 12],
                    buf[off + 13],
                    buf[off + 14],
                    buf[off + 15],
                ]);
                let word = (dword & 0xffff) as u16;
                let frag_off = (word >> 2) & 0x1fff;
                let frag_len = ((dword >> 15) & 0x7ff) as usize;
                let end = (off + 16 + frag_len).min(buf.len());
                let part = buf[off + 16..end].to_vec();
                if self.frags.len() > MAX_FRAGMENTS {
                    self.frags.clear();
                }
                let entry = self.frags.entry(id).or_insert_with(|| FragEntry {
                    parts: Vec::new(),
                    sr: None,
                    sr_pad: None,
                });
                if let Some((sr, pad)) = sr_ctx {
                    entry.sr = Some(sr);
                    entry.sr_pad = Some(pad);
                }
                entry.parts.push((frag_off, part));
                let assembled = assemble_fragments(&mut entry.parts);
                let Some(mut packet) = assembled else {
                    return Ok(());
                };
                if let Some(sr) = entry.sr.clone() {
                    if sr.mode != 0 {
                        sr.decrypt(&mut packet)
                            .map_err(|e| anyhow::anyhow!("SR fragment decrypt: {e}"))?;
                        if let Some(pad) = entry.sr_pad {
                            if packet.len() < pad as usize {
                                self.frags.remove(&id);
                                return Ok(());
                            }
                            packet.truncate(packet.len() - pad as usize);
                        }
                    }
                }
                self.frags.remove(&id);
                if is_ip(&packet) {
                    emit(&packet);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Wrap one uplink IP packet in a SEGRT/SR packet. The outer SR header uses the
/// same wire layout as the Android client: links are stored in reverse order,
/// and only the inner payload (not its 8-byte header) is outer-encrypted.
pub fn encode_uplink_sr(
    packet: &[u8],
    xor_key: &[u8],
    aes_key: &[u8],
    sid: u16,
    token: u32,
    encryption: u8,
    sr: &SrConfig,
) -> Result<Vec<u8>> {
    let linkcnt = sr.links.len().min(6);
    if linkcnt == 0 {
        bail!("SR uplink requires at least one link");
    }

    let is_ipv6 = packet.first().map(|b| b >> 4) == Some(6);
    let (inner_type, inner_enc) = if is_ipv6 {
        (protocol::PT_DATA_IPV6, 0)
    } else if encryption == 0 {
        (protocol::PT_DATA, 0)
    } else {
        (protocol::PT_DATA_ENC, encryption)
    };

    let mut inner_payload = packet.to_vec();
    match encryption {
        0 => {}
        1 if !is_ipv6 => crypto::xor(&mut inner_payload, xor_key),
        2 if !is_ipv6 => {
            let pad = (16 - inner_payload.len() % 16) % 16;
            inner_payload.resize(inner_payload.len() + pad, 0);
            crypto::aes_ecb_encrypt(&mut inner_payload, aes_key)
                .map_err(|e| anyhow::anyhow!("AES encrypt: {e}"))?;
        }
        _ => {}
    }

    // Outer encryption, when configured, is always 16-byte aligned.
    let outer_pad = if sr.mode == 0 {
        0
    } else {
        (16 - inner_payload.len() % 16) % 16
    };
    inner_payload.resize(inner_payload.len() + outer_pad, 0);
    if sr.mode != 0 {
        sr.encrypt(&mut inner_payload)
            .map_err(|e| anyhow::anyhow!("SR encrypt: {e}"))?;
    }

    let sr_header_len = 4 + 4 * linkcnt;
    let mut out = Vec::with_capacity(sr_header_len + 8 + inner_payload.len());
    out.push(protocol::PT_SEGRT);
    out.push((linkcnt - 1) as u8); // endpoint receives a terminal SR header
    out.push(linkcnt as u8);
    out.push(((outer_pad as u8) << 3) | (sr.mode & 7));
    for link in sr.links.iter().rev().take(linkcnt) {
        out.extend_from_slice(&link.to_be_bytes());
    }
    let header = protocol::pkhdr(inner_type, inner_enc, sid, token);
    out.extend_from_slice(&header);
    out.extend_from_slice(&inner_payload);
    Ok(out)
}

/// Build an SR monitor/echo request. The SR header carries no outer cipher;
/// the inner packet is a plain ECHO_REQUEST whose 40-byte payload is echoed by
/// the endpoint. The Android client uses this for per-link latency telemetry.
pub fn encode_sr_echo(sr: &SrConfig, sid: u16, token: u32, payload: &[u8]) -> Vec<u8> {
    let linkcnt = sr.links.len().clamp(1, 6);
    let mut out = Vec::with_capacity(4 + 4 * linkcnt + 8 + payload.len());
    out.push(protocol::PT_SEGRT);
    out.push((linkcnt - 1) as u8);
    out.push(linkcnt as u8);
    out.push(0); // no outer encryption / padding
    for link in sr.links.iter().rev().take(linkcnt) {
        out.extend_from_slice(&link.to_be_bytes());
    }
    out.extend_from_slice(&protocol::pkhdr(protocol::PT_ECHO_REQ, 0, sid, token));
    out.extend_from_slice(payload);
    out
}

/// Encode one uplink TUN packet for the new protocol. IPv6 is type 0x23 and
/// is never XORed; IPv4 is 0x14/0x18 depending on the negotiated mode.
pub fn encode_uplink(
    packet: &mut [u8],
    len: usize,
    xor_key: &[u8],
    aes_key: &[u8],
    sid: u16,
    token: u32,
    encryption: u8,
) -> Result<([u8; 8], usize)> {
    if len == 0 || len > packet.len() {
        bail!("invalid inner packet length");
    }
    match packet[0] >> 4 {
        6 => Ok((protocol::pkhdr(protocol::PT_DATA_IPV6, 0, sid, token), len)),
        4 => match encryption {
            0 => Ok((protocol::pkhdr(protocol::PT_DATA, 0, sid, token), len)),
            1 => {
                crypto::xor(&mut packet[..len], xor_key);
                Ok((protocol::pkhdr(protocol::PT_DATA_ENC, 1, sid, token), len))
            }
            2 => {
                let pad = (16 - len % 16) % 16;
                if len + pad > packet.len() {
                    bail!("AES padding exceeds upload slot");
                }
                packet[len..len + pad].fill(0);
                crypto::aes_ecb_encrypt(&mut packet[..len + pad], aes_key)
                    .map_err(|e| anyhow::anyhow!("AES encrypt: {e}"))?;
                Ok((
                    protocol::pkhdr(protocol::PT_DATA_ENC, 2, sid, token),
                    len + pad,
                ))
            }
            n => bail!("unsupported encryption mode {n}"),
        },
        _ => bail!("not an IPv4/IPv6 packet"),
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

fn assemble_fragments(parts: &mut [(u16, Vec<u8>)]) -> Option<Vec<u8>> {
    if parts.len() < 2 {
        return None;
    }
    parts.sort_by_key(|(off, _)| *off);
    let mut out = Vec::new();
    for (off, data) in parts.iter() {
        if *off as usize != out.len() {
            return None;
        }
        out.extend_from_slice(data);
    }
    Some(out)
}

fn is_ip(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    match packet[0] >> 4 {
        4 => packet.len() >= 20,
        6 => packet.len() >= 40,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_two_fragments_in_any_order() {
        let mut parts = vec![(4, b"ef".to_vec()), (0, b"abcd".to_vec())];
        assert_eq!(assemble_fragments(&mut parts).unwrap(), b"abcdef");
    }

    #[test]
    fn sr_uplink_round_trips_for_all_inner_modes() {
        let xor = [1u8; 8];
        let aes = [2u8; 16];
        for mode in 0..=2 {
            let sr = SrConfig {
                password: "0123456789abcdef".into(),
                links: vec![1, 2],
                mode,
                key_mode: crate::core::sr::SrKeyMode::Raw,
                local_id: 0,
            };
            for enc in 0..=2 {
                let mut raw = vec![0u8; 20];
                raw[0] = 0x45;
                raw[2..4].copy_from_slice(&20u16.to_be_bytes());
                raw[9] = 17;
                let wire =
                    encode_uplink_sr(&raw, &xor, &aes, 0x1234, 0x56789abc, enc, &sr).unwrap();
                let mut rx = TunnelRx::new(&xor, &aes, enc, 0x1234, 0x56789abc, Some(sr.clone()));
                let mut packets = Vec::new();
                rx.handle(&wire, &mut |packet| packets.push(packet.to_vec()))
                    .unwrap();
                assert_eq!(packets.len(), 1, "mode={mode} enc={enc}");
                assert_eq!(&packets[0][..20], &raw[..20], "mode={mode} enc={enc}");
            }
        }
    }

    #[test]
    fn rejects_gap() {
        let mut parts = vec![(0, b"ab".to_vec()), (3, b"cd".to_vec())];
        assert!(assemble_fragments(&mut parts).is_none());
    }
}
