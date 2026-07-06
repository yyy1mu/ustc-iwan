use std::net::SocketAddr;
use std::time::Instant;

pub struct Session {
    pub sid: u16,
    pub token: u32,
    pub addr: SocketAddr,
    pub ip: String,
    pub ip_bytes: [u8; 4],
    pub xor_key: Vec<u8>,
    pub enc: u8,
    #[allow(dead_code)]
    pub created: Instant,
}
