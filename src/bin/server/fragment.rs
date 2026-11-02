//! SR/IP fragment reassembly kept separate from handshake and data handling.

use crate::handler::ServerContext;
use iwan::core::tun;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct SrFragment {
    parts: Vec<(u16, Vec<u8>)>,
    eop: Option<usize>,
    created: Instant,
}

pub fn handle_fragment(raw: &[u8], sid: u16, token: u32, ctx: &ServerContext<'_>) {
    if raw.len() < 16 {
        return;
    }
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
    let id = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let dword = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let frag_off = ((dword >> 2) & 0x1fff) as usize;
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

pub fn reap_fragments(
    fragments: &Mutex<HashMap<(u16, u32), SrFragment>>,
    max_age: std::time::Duration,
) {
    let mut fragments = fragments.lock().unwrap();
    fragments.retain(|_, fragment| fragment.created.elapsed() < max_age);
}
