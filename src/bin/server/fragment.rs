//! SR/IP fragment reassembly table.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

struct Entry {
    parts: Vec<(u16, Vec<u8>)>,
    eop: Option<usize>,
    last_seen: Instant,
}

pub struct FragmentTable {
    inner: Mutex<HashMap<(u16, u32, u32), Entry>>,
    max_entries: usize,
}

impl FragmentTable {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(u16, u32, u32), Entry>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns a complete IP packet when the new fragment closes the set.
    pub fn push(
        &self,
        sid: u16,
        token: u32,
        id: u32,
        offset: u16,
        eop: bool,
        part: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut map = self.lock();
        if map.len() >= self.max_entries && !map.contains_key(&(sid, token, id)) {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| *key)
            {
                map.remove(&oldest);
            }
        }
        let now = Instant::now();
        let entry = map.entry((sid, token, id)).or_insert_with(|| Entry {
            parts: Vec::new(),
            eop: None,
            last_seen: now,
        });
        if entry.parts.iter().any(|(off, _)| *off == offset) {
            return None;
        }
        entry.last_seen = now;
        if eop {
            entry.eop = Some(offset as usize + part.len());
        }
        entry.parts.push((offset, part));
        entry.parts.sort_by_key(|(off, _)| *off);
        let mut out = Vec::new();
        for (off, data) in &entry.parts {
            if *off as usize != out.len() {
                return None;
            }
            out.extend_from_slice(data);
        }
        if entry.eop != Some(out.len()) {
            return None;
        }
        map.remove(&(sid, token, id));
        let version = out.first().map(|byte| byte >> 4)?;
        let valid = match version {
            4 => out.len() >= 20,
            6 => out.len() >= 40,
            _ => false,
        };
        valid.then_some(out)
    }

    pub fn reap(&self, max_age: Duration) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, entry| entry.last_seen.elapsed() < max_age);
        before.saturating_sub(map.len())
    }
}

pub fn handle_fragment(
    raw: &[u8],
    sid: u16,
    token: u32,
    sessions: &crate::session::SessionTable,
    fragments: &FragmentTable,
    tun: std::os::fd::RawFd,
) {
    if raw.len() < 16 || sessions.snapshot(sid, token).is_none() {
        return;
    }
    let id = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let dword = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let offset = ((dword >> 2) & 0x1fff) as u16;
    let len = ((dword >> 15) & 0x7ff) as usize;
    let end = (16 + len).min(raw.len());
    if end <= 16 {
        return;
    }
    if let Some(packet) = fragments.push(
        sid,
        token,
        id,
        offset,
        dword & 1 != 0,
        raw[16..end].to_vec(),
    ) {
        iwan::core::tun::tun_write(tun, &packet);
    }
}
