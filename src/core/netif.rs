use anyhow::{Context, Result};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// How the tunnel UDP socket should be bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindSpec {
    /// Interface name such as `eth0`, `en0` or a Windows alias.
    Device(String),
    /// Local source address.
    Ip(IpAddr),
}

impl BindSpec {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            anyhow::bail!("empty bind value");
        }
        match spec.parse::<IpAddr>() {
            Ok(ip) => Ok(Self::Ip(ip)),
            Err(_) => Ok(Self::Device(spec.to_string())),
        }
    }
}

impl fmt::Display for BindSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(name) => write!(f, "{name}"),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// A resolved source address plus an optional device for egress pinning.
pub struct BindTarget {
    pub addr: SocketAddr,
    pub device: Option<String>,
}

impl fmt::Display for BindTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.device, self.addr.ip()) {
            (Some(device), ip) if !ip.is_unspecified() => write!(f, "{device} ({ip})"),
            (Some(device), _) => write!(f, "{device}"),
            (None, ip) => write!(f, "{ip}"),
        }
    }
}

/// Resolve an explicit `--bind` value, or pick the active physical
/// interface (wired before wireless) when none is given.
pub fn resolve(bind: Option<&str>) -> Result<BindTarget> {
    let spec = bind
        .map(BindSpec::parse)
        .transpose()
        .context("invalid --bind value")?;
    Ok(match spec {
        Some(BindSpec::Ip(ip)) => BindTarget {
            addr: SocketAddr::new(ip, 0),
            device: None,
        },
        Some(BindSpec::Device(name)) => match interface_ipv4(&name) {
            Some(ip) => BindTarget {
                addr: SocketAddr::new(IpAddr::V4(ip), 0),
                device: Some(name),
            },
            None => BindTarget {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                device: Some(name),
            },
        },
        None => match pick_interface() {
            Some(iface) => BindTarget {
                addr: SocketAddr::new(IpAddr::V4(iface.ip), 0),
                device: Some(iface.name),
            },
            None => BindTarget {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                device: None,
            },
        },
    })
}

/// Pin the socket egress to a device where the platform supports it.
/// Source-address binding already happened via [`resolve`].
pub fn pin_to_device(sock: &UdpSocket, device: &str) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let Ok(name) = std::ffi::CString::new(device) else {
            return;
        };
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr() as *const libc::c_void,
                (device.len() + 1) as libc::socklen_t,
            )
        };
        if rc != 0 {
            eprintln!(
                "  warning: cannot pin socket to {device}: {} (source address still bound)",
                std::io::Error::last_os_error()
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;

        let Ok(name) = std::ffi::CString::new(device) else {
            return;
        };
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            eprintln!("  warning: unknown interface {device}");
            return;
        }
        let index = index as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                &index as *const _ as *const libc::c_void,
                std::mem::size_of_val(&index) as libc::socklen_t,
            )
        };
        if rc != 0 {
            eprintln!(
                "  warning: cannot bind socket to {device}: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (sock, device);
    }
}

struct Interface {
    name: String,
    ip: Ipv4Addr,
    wireless: bool,
    default_route: bool,
}

fn pick_interface() -> Option<Interface> {
    pick(interfaces())
}

/// Wired before wireless; within a class, the default-route interface first.
fn pick(mut interfaces: Vec<Interface>) -> Option<Interface> {
    interfaces.retain(|iface| !iface.ip.is_unspecified());
    interfaces.sort_by(|a, b| {
        (a.wireless, !a.default_route, &a.name).cmp(&(b.wireless, !b.default_route, &b.name))
    });
    interfaces.into_iter().next()
}

#[cfg(target_os = "linux")]
fn interfaces() -> Vec<Interface> {
    let default_dev = crate::core::route::capture_default().map(|(_, dev)| dev);
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return result;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Physical NICs have a `device` symlink; virtual ones do not.
        if name == "lo" || !entry.path().join("device").exists() {
            continue;
        }
        let operstate = std::fs::read_to_string(entry.path().join("operstate")).unwrap_or_default();
        if !matches!(operstate.trim(), "up" | "unknown") {
            continue;
        }
        let Some(ip) = interface_ipv4(&name) else {
            continue;
        };
        result.push(Interface {
            wireless: entry.path().join("wireless").exists(),
            default_route: default_dev.as_deref() == Some(name.as_str()),
            name,
            ip,
        });
    }
    result
}

#[cfg(target_os = "macos")]
fn interfaces() -> Vec<Interface> {
    let default_dev = default_route_device();
    let mut result = Vec::new();
    let Ok(output) = std::process::Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
    else {
        return result;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut port = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Hardware Port: ") {
            port = rest.trim().to_lowercase();
        }
        if let Some(rest) = line.strip_prefix("Device: ") {
            let name = rest.trim().to_string();
            if let Some(ip) = interface_ipv4(&name) {
                result.push(Interface {
                    wireless: port.contains("wi-fi") || port.contains("airport"),
                    default_route: default_dev.as_deref() == Some(name.as_str()),
                    name,
                    ip,
                });
            }
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn default_route_device() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|rest| rest.trim().to_string())
    })
}

#[cfg(target_os = "windows")]
fn interfaces() -> Vec<Interface> {
    // `Get-NetAdapter -Physical` excludes Wintun/TAP/Hyper-V and other virtual
    // adapters; Get-NetIPConfiguration alone would list them as candidates.
    let script = "$def=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
                  Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex; \
                  Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { \
                  $ip=(Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 \
                  -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress); \
                  if ($ip) { \"$($_.Name)|$ip|$($_.MediaType -eq '802.11')|$($_.ifIndex -eq $def)\" } }";
    let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().split('|');
            let name = parts.next()?.to_string();
            let ip = parts.next()?.parse().ok()?;
            let wireless = parts.next()?.eq_ignore_ascii_case("true");
            let default_route = parts
                .next()
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            Some(Interface {
                name,
                ip,
                wireless,
                default_route,
            })
        })
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn interfaces() -> Vec<Interface> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn interface_ipv4(name: &str) -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show", "dev", name])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_inet(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "macos")]
fn interface_ipv4(name: &str) -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ifconfig")
        .arg(name)
        .output()
        .ok()?;
    parse_inet(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "windows")]
fn interface_ipv4(name: &str) -> Option<Ipv4Addr> {
    let escaped = name.replace('\'', "''");
    let script = format!(
        "(Get-NetIPAddress -InterfaceAlias '{escaped}' -AddressFamily IPv4 \
         -ErrorAction SilentlyContinue).IPAddress"
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn interface_ipv4(_name: &str) -> Option<Ipv4Addr> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_inet(text: &str) -> Option<Ipv4Addr> {
    let mut tokens = text.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "inet" {
            return tokens.next()?.split('/').next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, wireless: bool, default_route: bool) -> Interface {
        Interface {
            name: name.to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 2),
            wireless,
            default_route,
        }
    }

    #[test]
    fn parses_bind_specs() {
        assert_eq!(
            BindSpec::parse("192.168.1.5").unwrap(),
            BindSpec::Ip("192.168.1.5".parse().unwrap())
        );
        assert_eq!(
            BindSpec::parse("::1").unwrap(),
            BindSpec::Ip("::1".parse().unwrap())
        );
        assert_eq!(
            BindSpec::parse(" eth0 ").unwrap(),
            BindSpec::Device("eth0".to_string())
        );
        assert!(BindSpec::parse("   ").is_err());
    }

    #[test]
    fn prefers_wired_then_default_route() {
        let candidates = vec![
            iface("wlan0", true, true),
            iface("eth0", false, false),
            iface("eth1", false, true),
        ];
        assert_eq!(pick(candidates).unwrap().name, "eth1");
    }

    #[test]
    fn falls_back_to_wireless_and_handles_empty() {
        let candidates = vec![iface("wlan1", true, false), iface("wlan0", true, true)];
        assert_eq!(pick(candidates).unwrap().name, "wlan0");
        assert!(pick(Vec::new()).is_none());
    }
}
