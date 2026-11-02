//! Idempotent server-side NAT setup.

use std::process::Command;

pub fn setup(subnet: &str, nat_if: &str) -> bool {
    let exists = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            nat_if,
            "-j",
            "MASQUERADE",
        ])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if exists {
        println!("iptables: existing MASQUERADE {subnet} -> {nat_if}");
        return false;
    }
    let ok = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            nat_if,
            "-j",
            "MASQUERADE",
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if ok {
        println!("iptables: MASQUERADE {subnet} -> {nat_if}");
    } else {
        eprintln!("iptables: failed to add MASQUERADE {subnet} -> {nat_if}");
    }
    ok
}

pub fn remove(subnet: &str, nat_if: &str) {
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            subnet,
            "-o",
            nat_if,
            "-j",
            "MASQUERADE",
        ])
        .status();
}
