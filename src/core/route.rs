use super::{protocol, util};

pub fn capture_default() -> Option<(String, String)> {
    let o = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&o.stdout);
    let (mut gw, mut dev) = (None, None);
    let mut it = s.split_whitespace();
    while let Some(w) = it.next() {
        if w == "via" {
            gw = it.next().map(|x| x.to_string());
        }
        if w == "dev" {
            dev = it.next().map(|x| x.to_string());
        }
    }
    match (gw, dev) {
        (Some(g), Some(d)) => Some((g, d)),
        _ => None,
    }
}

pub fn local_subnet(dev: &str) -> Option<String> {
    let o = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", dev])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&o.stdout);
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "inet" {
            if let Some(cidr) = parts[1..].iter().find(|x| x.contains('/')) {
                if let Some((ip, plen)) = cidr.split_once('/') {
                    let plen: u8 = plen.parse().unwrap_or(24);
                    let mask = if plen == 0 {
                        0
                    } else {
                        !((1u32 << (32 - plen)) - 1)
                    };
                    let net = u32::from_be_bytes(protocol::s2ip4(ip)) & mask;
                    let b = net.to_be_bytes();
                    return Some(format!("{}.{}.{}.{}/{}", b[0], b[1], b[2], b[3], plen));
                }
            }
        }
    }
    None
}

pub fn setup(
    tun: &str,
    tun_ip: &str,
    mtu: u16,
    srv: &str,
    ogw: &str,
    odev: &str,
    routes: &[String],
) {
    let _ = util::ip_run(&["addr", "flush", "dev", tun]);
    util::ip_run(&["link", "set", tun, "up"]);
    util::ip_run(&["link", "set", "dev", tun, "mtu", &mtu.to_string()]);
    util::ip_run(&["addr", "add", &format!("{tun_ip}/24"), "dev", tun]);
    util::ip_run(&[
        "route",
        "add",
        &format!("{srv}/32"),
        "via",
        ogw,
        "dev",
        odev,
    ]);
    util::ip_run(&["route", "flush", "cache"]);

    for c in routes {
        if c == "default" || c == "0.0.0.0/0" {
            if let Some(loc) = local_subnet(odev) {
                util::ip_run(&["route", "replace", &loc, "dev", odev]);
                println!("preserved local subnet {loc}");
            }
            util::ip_run(&["route", "replace", "default", "dev", tun]);
        } else {
            util::ip_run(&["route", "replace", c, "dev", tun]);
        }
        util::ip_run(&["route", "flush", "cache"]);
    }
}

pub fn teardown(tun: &str, srv: &str, ogw: &str, odev: &str, routes: &[String]) {
    for c in routes {
        if c == "default" || c == "0.0.0.0/0" {
            let _ = util::ip_run(&["route", "del", "default"]);
            let _ = util::ip_run(&["route", "add", "default", "via", ogw, "dev", odev]);
        } else {
            let _ = util::ip_run(&["route", "del", c]);
        }
    }
    let _ = util::ip_run(&["route", "del", &format!("{srv}/32")]);
    let _ = util::ip_run(&["addr", "flush", "dev", tun]);
    let _ = util::ip_run(&["link", "set", tun, "down"]);
    let _ = util::ip_run(&["route", "flush", "cache"]);
}
