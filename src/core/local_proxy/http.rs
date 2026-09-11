use super::flow::{HttpMode, ProxyError, Step};

const MAX_HTTP_HEAD: usize = 64 * 1024;

enum HttpRequest {
    Connect {
        host: String,
        port: u16,
    },
    Forward {
        host: String,
        port: u16,
        rewritten: Vec<u8>,
    },
}

/// Parse a proxy HTTP request head. Returns `Ok(None)` when more bytes are needed.
fn parse_http_request(input: &[u8]) -> Result<Option<(HttpRequest, usize)>, ProxyError> {
    let Some(end) = find_header_end(input) else {
        return if input.len() > MAX_HTTP_HEAD {
            Err(ProxyError::BadRequest)
        } else {
            Ok(None)
        };
    };
    let head_len = end + 4;
    let head = std::str::from_utf8(&input[..end]).map_err(|_| ProxyError::BadRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ProxyError::BadRequest)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ProxyError::BadRequest)?;
    let target = parts.next().ok_or(ProxyError::BadRequest)?;
    let version = parts.next().ok_or(ProxyError::BadRequest)?;
    if !version.starts_with("HTTP/") {
        return Err(ProxyError::BadRequest);
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target).ok_or(ProxyError::BadRequest)?;
        return Ok(Some((HttpRequest::Connect { host, port }, head_len)));
    }

    let Ok(url) = url::Url::parse(target) else {
        return Err(ProxyError::BadRequest);
    };
    if url.scheme() != "http" {
        return Err(ProxyError::CommandNotSupported);
    }
    let host = url.host_str().ok_or(ProxyError::BadRequest)?.to_string();
    let port = url.port_or_known_default().ok_or(ProxyError::BadRequest)?;

    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut rewritten = Vec::with_capacity(head_len);
    rewritten.extend_from_slice(format!("{method} {path} {version}\r\n").as_bytes());
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or_default().trim();
        if name.eq_ignore_ascii_case("Proxy-Connection")
            || name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Connection")
            || name.eq_ignore_ascii_case("Keep-Alive")
        {
            continue;
        }
        rewritten.extend_from_slice(line.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(Some((
        HttpRequest::Forward {
            host,
            port,
            rewritten,
        },
        head_len,
    )))
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if tail.is_empty() => 443,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match target.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), port.parse().ok()?)),
        None => Some((target.to_string(), 443)),
    }
}

pub(super) fn request(input: &[u8]) -> Step {
    match parse_http_request(input) {
        Err(error) => Step::Fail(error),
        Ok(None) => Step::Wait,
        Ok(Some((HttpRequest::Connect { host, port }, consumed))) => Step::Open {
            host,
            port,
            consumed,
            mode: Some(HttpMode::Connect),
            rewritten: None,
        },
        Ok(Some((
            HttpRequest::Forward {
                host,
                port,
                rewritten,
            },
            consumed,
        ))) => Step::Open {
            host,
            port,
            consumed,
            mode: Some(HttpMode::Forward),
            rewritten: Some(rewritten),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_connect_request() {
        let request = b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n";
        let (parsed, consumed) = parse_http_request(request).unwrap().unwrap();
        assert_eq!(consumed, request.len());
        match parsed {
            HttpRequest::Connect { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 8443);
            }
            HttpRequest::Forward { .. } => panic!("expected CONNECT"),
        }
    }

    #[test]
    fn rewrites_absolute_uri_requests() {
        let request = b"GET http://example.com/path?q=1 HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Proxy-Connection: keep-alive\r\n\
                        Accept: */*\r\n\r\n";
        let (parsed, consumed) = parse_http_request(request).unwrap().unwrap();
        assert_eq!(consumed, request.len());
        match parsed {
            HttpRequest::Forward {
                host,
                port,
                rewritten,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
                let text = String::from_utf8(rewritten).unwrap();
                assert!(text.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
                assert!(text.contains("Host: example.com\r\n"));
                assert!(text.contains("Accept: */*\r\n"));
                assert!(!text.to_lowercase().contains("proxy-connection"));
                assert!(text.ends_with("Connection: close\r\n\r\n"));
            }
            HttpRequest::Connect { .. } => panic!("expected forward request"),
        }
    }

    #[test]
    fn rejects_incomplete_or_invalid_http_requests() {
        assert!(parse_http_request(b"CONNECT example.com:443 HTTP/1.1\r\n")
            .unwrap()
            .is_none());
        assert!(matches!(
            parse_http_request(b"CONNECT example.com:bad HTTP/1.1\r\n\r\n"),
            Err(ProxyError::BadRequest)
        ));
        assert!(matches!(
            parse_http_request(b"GET https://example.com/ HTTP/1.1\r\n\r\n"),
            Err(ProxyError::CommandNotSupported)
        ));
        assert!(matches!(
            parse_http_request(b"GET /relative HTTP/1.1\r\n\r\n"),
            Err(ProxyError::BadRequest)
        ));
    }

    #[test]
    fn parses_connect_targets() {
        assert_eq!(
            split_host_port("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            split_host_port("1.2.3.4"),
            Some(("1.2.3.4".to_string(), 443))
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:8443"),
            Some(("2001:db8::1".to_string(), 8443))
        );
        assert_eq!(split_host_port("example.com:bad"), None);
    }
}
