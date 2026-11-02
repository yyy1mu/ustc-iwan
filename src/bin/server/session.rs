use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

pub struct Session {
    pub sid: u16,
    pub token: u32,
    pub addr: SocketAddr,
    pub ip: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub xor_key: Vec<u8>,
    pub aes_key: Vec<u8>,
    pub enc: u8,
    pub srlink: Option<u32>,
    pub last_seen: Instant,
}

#[derive(Clone)]
pub struct SessionSnapshot {
    pub sid: u16,
    pub token: u32,
    pub addr: SocketAddr,
    pub xor_key: Vec<u8>,
    pub aes_key: Vec<u8>,
    pub enc: u8,
    pub srlink: Option<u32>,
}

struct Pool {
    sessions: HashMap<u16, Session>,
    free_ipv4: Vec<Ipv4Addr>,
    free_ipv6: Vec<Ipv6Addr>,
    next_ipv4: u32,
    next_ipv6: u32,
    last_ipv4: u32,
}

pub struct SessionTable {
    pool: Mutex<Pool>,
    max_sessions: usize,
}

impl SessionTable {
    pub fn new(max_sessions: usize, subnet_ip: Ipv4Addr, prefix: u8) -> Self {
        let base = u32::from(subnet_ip);
        let mask = if prefix == 0 {
            0
        } else {
            !((1u32 << (32 - prefix)) - 1)
        };
        let network = base & mask;
        let broadcast = network | !mask;
        Self {
            pool: Mutex::new(Pool {
                sessions: HashMap::new(),
                free_ipv4: Vec::new(),
                free_ipv6: Vec::new(),
                next_ipv4: network.saturating_add(2),
                next_ipv6: 1,
                last_ipv4: broadcast.saturating_sub(1),
            }),
            max_sessions,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Pool> {
        self.pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn allocate_ipv4(&self) -> Option<Ipv4Addr> {
        let mut pool = self.lock();
        if let Some(ip) = pool.free_ipv4.pop() {
            return Some(ip);
        }
        if pool.next_ipv4 > pool.last_ipv4 {
            return None;
        }
        let ip = Ipv4Addr::from(pool.next_ipv4);
        pool.next_ipv4 = pool.next_ipv4.saturating_add(1);
        Some(ip)
    }

    pub fn allocate_ipv6(&self, requested: Option<Ipv6Addr>, server: Ipv6Addr) -> Ipv6Addr {
        if let Some(ip) = requested {
            return ip;
        }
        let mut pool = self.lock();
        if let Some(ip) = pool.free_ipv6.pop() {
            return ip;
        }
        let ip = Ipv6Addr::from(u128::from(server) + u128::from(pool.next_ipv6));
        pool.next_ipv6 = pool.next_ipv6.saturating_add(1);
        ip
    }

    pub fn release_ipv4(&self, ip: Ipv4Addr) {
        self.lock().free_ipv4.push(ip);
    }

    pub fn release_ipv6(&self, ip: Ipv6Addr) {
        self.lock().free_ipv6.push(ip);
    }

    pub fn insert(&self, session: Session) -> Result<(), &'static str> {
        let mut pool = self.lock();
        if pool.sessions.len() >= self.max_sessions {
            return Err("session capacity reached");
        }
        if pool.sessions.contains_key(&session.sid) {
            return Err("session id collision");
        }
        pool.sessions.insert(session.sid, session);
        Ok(())
    }

    pub fn snapshot(&self, sid: u16, token: u32) -> Option<SessionSnapshot> {
        let mut pool = self.lock();
        let session = pool.sessions.get_mut(&sid)?;
        if session.token != token {
            return None;
        }
        session.last_seen = Instant::now();
        Some(SessionSnapshot {
            sid: session.sid,
            token: session.token,
            addr: session.addr,
            xor_key: session.xor_key.clone(),
            aes_key: session.aes_key.clone(),
            enc: session.enc,
            srlink: session.srlink,
        })
    }

    pub fn find_by_ip(&self, ip: Ipv4Addr) -> Option<SessionSnapshot> {
        let pool = self.lock();
        pool.sessions
            .values()
            .find(|session| session.ip == ip)
            .map(|session| SessionSnapshot {
                sid: session.sid,
                token: session.token,
                addr: session.addr,
                xor_key: session.xor_key.clone(),
                aes_key: session.aes_key.clone(),
                enc: session.enc,
                srlink: session.srlink,
            })
    }

    pub fn find_by_ipv6(&self, ip: Ipv6Addr) -> Option<SessionSnapshot> {
        let pool = self.lock();
        pool.sessions
            .values()
            .find(|session| session.ipv6 == ip)
            .map(|session| SessionSnapshot {
                sid: session.sid,
                token: session.token,
                addr: session.addr,
                xor_key: session.xor_key.clone(),
                aes_key: session.aes_key.clone(),
                enc: session.enc,
                srlink: session.srlink,
            })
    }

    pub fn remove(&self, sid: u16, token: u32) -> Option<Session> {
        let mut pool = self.lock();
        let matches = pool.sessions.get(&sid).is_some_and(|s| s.token == token);
        if !matches {
            return None;
        }
        let session = pool.sessions.remove(&sid)?;
        pool.free_ipv4.push(session.ip);
        pool.free_ipv6.push(session.ipv6);
        Some(session)
    }

    pub fn reap(&self, idle: std::time::Duration) -> usize {
        let mut pool = self.lock();
        let stale: Vec<u16> = pool
            .sessions
            .iter()
            .filter(|(_, session)| session.last_seen.elapsed() >= idle)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in &stale {
            if let Some(session) = pool.sessions.remove(sid) {
                pool.free_ipv4.push(session.ip);
                pool.free_ipv6.push(session.ipv6);
            }
        }
        stale.len()
    }
}
