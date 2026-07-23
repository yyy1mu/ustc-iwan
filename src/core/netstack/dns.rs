use anyhow::{Context, Result};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::mpsc::Sender;
use std::time::Duration;

pub(crate) const DNS_SERVER: &str = "114.114.114.114:53";
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct DnsResult {
    pub(crate) flow_id: u64,
    pub(crate) domain: String,
    pub(crate) port: u16,
    pub(crate) result: std::result::Result<Ipv4Addr, ()>,
}

pub(crate) fn spawn_ipv4_query(flow_id: u64, domain: String, port: u16, sender: Sender<DnsResult>) {
    std::thread::spawn(move || {
        let result = resolve_ipv4(&domain).map_err(|_| ());
        let _ = sender.send(DnsResult {
            flow_id,
            domain,
            port,
            result,
        });
    });
}

fn resolve_ipv4(domain: &str) -> Result<Ipv4Addr> {
    let query_id = rand::random();
    let query = build_a_query(query_id, domain)?;
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind DNS socket")?;
    socket.set_read_timeout(Some(DNS_TIMEOUT))?;
    socket.set_write_timeout(Some(DNS_TIMEOUT))?;
    socket
        .send_to(&query, DNS_SERVER)
        .with_context(|| format!("query DNS server {DNS_SERVER}"))?;

    let mut response = [0u8; 4096];
    let (len, source) = socket
        .recv_from(&mut response)
        .context("receive DNS response")?;
    if source.ip() != Ipv4Addr::new(114, 114, 114, 114) {
        anyhow::bail!("DNS response from unexpected server {source}");
    }
    parse_a_response(query_id, &response[..len])
}

fn build_a_query(id: u16, domain: &str) -> Result<Vec<u8>> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() || domain.len() > 253 {
        anyhow::bail!("invalid DNS name");
    }
    let mut query = Vec::with_capacity(12 + domain.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("invalid DNS label");
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn parse_a_response(id: u16, packet: &[u8]) -> Result<Ipv4Addr> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id {
        anyhow::bail!("invalid DNS response");
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        anyhow::bail!("DNS query failed");
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        offset = offset.checked_add(4).context("truncated DNS question")?;
        if offset > packet.len() {
            anyhow::bail!("truncated DNS question");
        }
    }
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            anyhow::bail!("truncated DNS answer");
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let data_len = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + data_len > packet.len() {
            anyhow::bail!("truncated DNS record");
        }
        if record_type == 1 && class == 1 && data_len == 4 {
            return Ok(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
        }
        offset += data_len;
    }
    anyhow::bail!("DNS name has no IPv4 address")
}

fn skip_name(packet: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        let len = *packet.get(offset).context("truncated DNS name")?;
        if len & 0xc0 == 0xc0 {
            if offset + 2 > packet.len() {
                anyhow::bail!("truncated DNS compression pointer");
            }
            return Ok(offset + 2);
        }
        if len & 0xc0 != 0 {
            anyhow::bail!("invalid DNS label");
        }
        offset += 1;
        if len == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(len as usize)
            .context("DNS name overflow")?;
        if offset > packet.len() {
            anyhow::bail!("truncated DNS label");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_a_messages() {
        let query = build_a_query(0x1234, "www.example.com").unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert!(query.windows(5).any(|part| part == b"\x03www\x07"));

        let mut response = query;
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4,
        ]);
        assert_eq!(
            parse_a_response(0x1234, &response).unwrap(),
            Ipv4Addr::new(1, 2, 3, 4)
        );
    }

    #[test]
    fn rejects_invalid_names_and_responses() {
        assert!(build_a_query(1, "").is_err());
        assert!(build_a_query(1, "bad..name").is_err());
        assert!(build_a_query(1, &format!("{}.com", "x".repeat(64))).is_err());
        assert!(parse_a_response(1, &[0; 12]).is_err());
    }
}
