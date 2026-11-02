use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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
    #[allow(dead_code)]
    pub pipeid: Option<u16>,
    #[allow(dead_code)]
    pub pipeidx: Option<u16>,
    pub srlink: Option<u32>,
    #[allow(dead_code)]
    pub created: Instant,
}
