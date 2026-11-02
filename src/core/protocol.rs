use super::crypto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    OpenReject = 0x11,
    OpenAck = 0x12,
    Open = 0x13,
    Data = 0x14,
    EchoRequest = 0x15,
    EchoResponse = 0x16,
    Close = 0x17,
    DataEncrypted = 0x18,
    DataDup = 0x19,
    DataEncDup = 0x20,
    IpFragment = 0x22,
    DataIpv6 = 0x23,
    IpFragmentIpv6 = 0x24,
    SegmentRouting = 0x28,
    PingRequest = 0x29,
    PingResponse = 0x2A,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x11 => Self::OpenReject,
            0x12 => Self::OpenAck,
            0x13 => Self::Open,
            0x14 => Self::Data,
            0x15 => Self::EchoRequest,
            0x16 => Self::EchoResponse,
            0x17 => Self::Close,
            0x18 => Self::DataEncrypted,
            0x19 => Self::DataDup,
            0x20 => Self::DataEncDup,
            0x22 => Self::IpFragment,
            0x23 => Self::DataIpv6,
            0x24 => Self::IpFragmentIpv6,
            0x28 => Self::SegmentRouting,
            0x29 => Self::PingRequest,
            0x2A => Self::PingResponse,
            _ => return None,
        })
    }
}

pub const PT_OPEN_REJECT: u8 = 0x11;
pub const PT_OPEN_ACK: u8 = 0x12;
pub const PT_OPEN: u8 = 0x13;
pub const PT_DATA: u8 = 0x14;
pub const PT_ECHO_REQ: u8 = 0x15;
pub const PT_ECHO_RES: u8 = 0x16;
pub const PT_CLOSE: u8 = 0x17;
pub const PT_DATA_ENC: u8 = 0x18;
pub const PT_DATA_DUP: u8 = 0x19;
pub const PT_DATA_ENC_DUP: u8 = 0x20;
pub const PT_IPFRAG: u8 = 0x22;
pub const PT_IPFRAG_ALT: u8 = 0x24;
pub const PT_DATA_IPV6: u8 = 0x23;
pub const PT_SEGRT: u8 = 0x28;
pub const PT_PING_REQ: u8 = 0x29;
pub const PT_PING_RSP: u8 = 0x2A;

pub const T_USERNAME: u8 = 0x01;
pub const T_PASSWORD: u8 = 0x02;
pub const T_MTU: u8 = 0x03;
pub const T_IP: u8 = 0x04;
pub const T_DNS: u8 = 0x05;
pub const T_GATEWAY: u8 = 0x06;
pub const T_ENCRYPT: u8 = 0x08;
pub const T_DUPPKT: u8 = 0x09;
pub const T_PIPE: u8 = 0x0A;
pub const T_IPV6: u8 = 0x0B;
pub const T_DNS6: u8 = 0x0C;
pub const T_GATEWAY6: u8 = 0x0D;
pub const T_AUTH_VERIFY: u8 = 0x0F;
pub const T_ERR_MSG: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvType {
    Username = 0x01,
    Password = 0x02,
    Mtu = 0x03,
    Ip = 0x04,
    Dns = 0x05,
    Gateway = 0x06,
    Netmask = 0x07,
    Encrypt = 0x08,
    DupPkt = 0x09,
    Link = 0x0A,
    Ip6 = 0x0B,
    Dns6 = 0x0C,
    Gateway6 = 0x0D,
    AuthVerify = 0x0F,
    ErrMsg = 0x10,
}

impl TlvType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x01 => Self::Username,
            0x02 => Self::Password,
            0x03 => Self::Mtu,
            0x04 => Self::Ip,
            0x05 => Self::Dns,
            0x06 => Self::Gateway,
            0x07 => Self::Netmask,
            0x08 => Self::Encrypt,
            0x09 => Self::DupPkt,
            0x0A => Self::Link,
            0x0B => Self::Ip6,
            0x0C => Self::Dns6,
            0x0D => Self::Gateway6,
            0x0F => Self::AuthVerify,
            0x10 => Self::ErrMsg,
            _ => return None,
        })
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub typ: TlvType,
    pub value: Vec<u8>,
}

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

pub fn parse_tlvs(data: &[u8]) -> Vec<Tlv> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = data[i + 1] as usize;
        if len < 2 || i + len > data.len() {
            break;
        }
        if let Some(typ) = TlvType::from_u8(data[i]) {
            out.push(Tlv {
                typ,
                value: data[i + 2..i + len].to_vec(),
            });
        }
        i += len;
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
