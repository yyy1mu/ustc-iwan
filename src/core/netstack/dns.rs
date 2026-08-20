use anyhow::{Context, Result};
use std::fmt;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU16;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_DNS: &str = "114.114.114.114:53";
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
pub enum DnsResolver {
    Udp(SocketAddr),
    Dot { host: String, port: NonZeroU16 },
    Doh { url: String },
}

impl DnsResolver {
    /// Parse a resolver spec: `ip[:port]` (plain UDP), `tls://host[:port]`
    /// (DNS over TLS) or `https://...` (DNS over HTTPS).
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if let Some(rest) = spec.strip_prefix("tls://") {
            let (host, port) = split_host_port(rest, 853)?;
            return Ok(Self::Dot { host, port });
        }
        if spec.starts_with("https://") {
            let url = url::Url::parse(spec)
                .with_context(|| format!("invalid DNS-over-HTTPS URL: {spec}"))?;
            if url.host_str().is_none() || url.path().len() <= 1 {
                anyhow::bail!("invalid DNS-over-HTTPS URL: {spec}");
            }
            return Ok(Self::Doh { url: spec.into() });
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            return Ok(Self::Udp(addr));
        }
        if let Ok(ip) = spec.parse::<std::net::IpAddr>() {
            return Ok(Self::Udp(SocketAddr::new(ip, 53)));
        }
        let addr: SocketAddr = format!("{spec}:53")
            .parse()
            .with_context(|| format!("invalid DNS resolver: {spec}"))?;
        Ok(Self::Udp(addr))
    }
}

impl fmt::Display for DnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "{addr}"),
            Self::Dot { host, port } => write!(f, "tls://{host}:{port}"),
            Self::Doh { url } => write!(f, "{url}"),
        }
    }
}

fn split_host_port(spec: &str, default_port: u16) -> Result<(String, NonZeroU16)> {
    let default_port = NonZeroU16::new(default_port).expect("default DNS port is zero");
    if spec.is_empty() {
        anyhow::bail!("empty DNS host");
    }
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed bracket in DNS host: {spec}"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => parse_dns_port(port, spec)?,
            None if tail.is_empty() => default_port,
            None => anyhow::bail!("invalid DNS host: {spec}"),
        };
        (host.to_string(), port)
    } else {
        if spec.matches(':').count() > 1 {
            anyhow::bail!("wrap IPv6 DNS hosts in brackets: [{spec}]");
        }
        match spec.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => {
                (host.to_string(), parse_dns_port(port, spec)?)
            }
            _ => (spec.to_string(), default_port),
        }
    };
    if host.is_empty() {
        anyhow::bail!("empty DNS host");
    }
    Ok((host, port))
}

fn parse_dns_port(port: &str, spec: &str) -> Result<NonZeroU16> {
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid DNS port in {spec}"))?;
    NonZeroU16::new(port).ok_or_else(|| anyhow::anyhow!("invalid DNS port in {spec}"))
}

pub(crate) struct DnsResult {
    pub(crate) flow_id: u64,
    pub(crate) domain: String,
    pub(crate) port: u16,
    pub(crate) result: std::result::Result<Ipv4Addr, ()>,
}

pub(crate) fn spawn_ipv4_query(
    flow_id: u64,
    domain: String,
    port: u16,
    resolver: DnsResolver,
    sender: Sender<DnsResult>,
) {
    std::thread::spawn(move || {
        let result = resolve_ipv4(&domain, &resolver).map_err(|_| ());
        let _ = sender.send(DnsResult {
            flow_id,
            domain,
            port,
            result,
        });
    });
}

fn resolve_ipv4(domain: &str, resolver: &DnsResolver) -> Result<Ipv4Addr> {
    let query_id = rand::random();
    let query = build_a_query(query_id, domain)?;
    let response = match resolver {
        DnsResolver::Udp(addr) => udp_query(&query, *addr)?,
        DnsResolver::Dot { host, port } => dot_query(&query, host, port.get())?,
        DnsResolver::Doh { url } => doh_query(&query, url)?,
    };
    parse_a_response(query_id, &response)
}

fn udp_query(query: &[u8], addr: SocketAddr) -> Result<Vec<u8>> {
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr).context("bind DNS socket")?;
    socket.set_read_timeout(Some(DNS_TIMEOUT))?;
    socket.set_write_timeout(Some(DNS_TIMEOUT))?;
    socket
        .connect(addr)
        .with_context(|| format!("connect DNS server {addr}"))?;
    socket
        .send(query)
        .with_context(|| format!("query DNS server {addr}"))?;

    let mut response = vec![0u8; 4096];
    let len = socket.recv(&mut response).context("receive DNS response")?;
    response.truncate(len);
    Ok(response)
}

fn dot_query(query: &[u8], host: &str, port: u16) -> Result<Vec<u8>> {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};

    let server_name = ServerName::try_from(host)
        .map_err(|_| anyhow::anyhow!("invalid DNS-over-TLS host: {host}"))?
        .to_owned();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();

    let mut stream = std::net::TcpStream::connect((host, port)).context("connect DNS-over-TLS")?;
    stream.set_read_timeout(Some(DNS_TIMEOUT))?;
    stream.set_write_timeout(Some(DNS_TIMEOUT))?;
    let mut conn =
        ClientConnection::new(Arc::new(config), server_name).context("TLS handshake setup")?;
    let mut tls = Stream::new(&mut conn, &mut stream);

    let mut frame = Vec::with_capacity(2 + query.len());
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    std::io::Write::write_all(&mut tls, &frame).context("send DNS-over-TLS query")?;

    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf)
        .context("read DNS-over-TLS length")?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut response = vec![0u8; len];
    tls.read_exact(&mut response)
        .context("read DNS-over-TLS response")?;
    Ok(response)
}

fn doh_query(query: &[u8], url: &str) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(DNS_TIMEOUT)
        .try_proxy_from_env(false)
        .build();
    let response = agent
        .post(url)
        .set("Content-Type", "application/dns-message")
        .set("Accept", "application/dns-message")
        .send_bytes(query)
        .with_context(|| format!("query DNS-over-HTTPS server {url}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .context("read DNS-over-HTTPS response")?;
    Ok(body)
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
    fn parses_resolver_specs() {
        assert!(matches!(
            DnsResolver::parse("223.5.5.5").unwrap(),
            DnsResolver::Udp(addr) if addr.to_string() == "223.5.5.5:53"
        ));
        assert!(matches!(
            DnsResolver::parse("223.5.5.5:5353").unwrap(),
            DnsResolver::Udp(addr) if addr.to_string() == "223.5.5.5:5353"
        ));
        assert!(matches!(
            DnsResolver::parse("tls://dns.alidns.com").unwrap(),
            DnsResolver::Dot { host, port } if host == "dns.alidns.com" && port.get() == 853
        ));
        assert!(matches!(
            DnsResolver::parse("tls://dns.alidns.com:8543").unwrap(),
            DnsResolver::Dot { port, .. } if port.get() == 8543
        ));
        assert!(matches!(
            DnsResolver::parse("tls://[2001:db8::1]:853").unwrap(),
            DnsResolver::Dot { host, port } if host == "2001:db8::1" && port.get() == 853
        ));
        assert!(matches!(
            DnsResolver::parse("tls://[2001:db8::1]").unwrap(),
            DnsResolver::Dot { host, port } if host == "2001:db8::1" && port.get() == 853
        ));
        assert!(matches!(
            DnsResolver::parse("https://dns.alidns.com/dns-query").unwrap(),
            DnsResolver::Doh { url } if url == "https://dns.alidns.com/dns-query"
        ));
        assert!(matches!(
            DnsResolver::parse("2001:4860:4860::8888").unwrap(),
            DnsResolver::Udp(addr) if addr.to_string() == "[2001:4860:4860::8888]:53"
        ));
        assert!(matches!(
            DnsResolver::parse("[2001:4860:4860::8888]:5353").unwrap(),
            DnsResolver::Udp(addr) if addr.to_string() == "[2001:4860:4860::8888]:5353"
        ));
        assert!(DnsResolver::parse("tls://").is_err());
        assert!(DnsResolver::parse("tls://dns.alidns.com:0").is_err());
        assert!(DnsResolver::parse("tls://2001:db8::1").is_err());
        assert!(DnsResolver::parse("tls://[2001:db8::1").is_err());
        assert!(DnsResolver::parse("https://").is_err());
        assert!(DnsResolver::parse("https:// not a url").is_err());
        assert!(DnsResolver::parse("https://dns.alidns.com").is_err());
        assert!(DnsResolver::parse("https://:443/dns-query").is_err());
        assert!(DnsResolver::parse("not a resolver").is_err());
    }

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
