use super::crypto;

pub const PT_OPEN_REJECT: u8 = 0x11;
pub const PT_OPEN_ACK: u8 = 0x12;
pub const PT_OPEN: u8 = 0x13;
pub const PT_DATA: u8 = 0x14;
pub const PT_ECHO_REQ: u8 = 0x15;
pub const PT_ECHO_RES: u8 = 0x16;
pub const PT_CLOSE: u8 = 0x17;
pub const PT_DATA_ENC: u8 = 0x18;
pub const PT_PING_REQ: u8 = 0x29;
pub const PT_PING_RSP: u8 = 0x2A;

pub const T_USERNAME: u8 = 0x01;
pub const T_PASSWORD: u8 = 0x02;
pub const T_MTU: u8 = 0x03;
pub const T_IP: u8 = 0x04;
pub const T_DNS: u8 = 0x05;
pub const T_GATEWAY: u8 = 0x06;
pub const T_ENCRYPT: u8 = 0x08;
pub const T_AUTH_VERIFY: u8 = 0x0F;
pub const T_ERR_MSG: u8 = 0x10;

pub fn pkhdr(typ: u8, enc: u8, sid: u16, tok: u32) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = typ;
    h[1] = enc;
    h[2..4].copy_from_slice(&sid.to_be_bytes());
    h[4..8].copy_from_slice(&tok.to_be_bytes());
    h
}

pub fn sig8(h8: &[u8]) -> [u8; 16] {
    let mut x = [0u8; 10];
    x[..8].copy_from_slice(h8);
    x[8..].copy_from_slice(b"mw");
    crypto::md5(&x)
}

pub fn ctrl_pkt(h8: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    [h8.as_slice(), &sig8(h8), payload].concat()
}

pub fn data_pkt(h8: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    [h8.as_slice(), payload].concat()
}

pub fn tlv(typ: u8, val: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + val.len());
    v.push(typ);
    v.push((val.len() + 2) as u8);
    v.extend_from_slice(val);
    v
}

pub fn parse_tlvs(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let t = data[i];
        let l = data[i + 1] as usize;
        if l < 2 || i + l > data.len() {
            break;
        }
        out.push((t, data[i + 2..i + l].to_vec()));
        i += l;
    }
    out
}

pub fn verify_sig(buf: &[u8]) -> bool {
    buf.len() >= 24 && sig8(&buf[..8]) == buf[8..24]
}

pub fn ip_to_string(b: &[u8]) -> String {
    if b.len() < 4 {
        "??".into()
    } else {
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }
}

pub fn s2ip4(s: &str) -> [u8; 4] {
    let p: Vec<u8> = s.split('.').map(|x| x.parse().unwrap()).collect();
    [p[0], p[1], p[2], p[3]]
}
