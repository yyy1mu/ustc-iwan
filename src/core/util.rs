use std::process::{Command, Stdio};
use std::sync::OnceLock;

pub fn debug_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("IWAN_DEBUG")
            .map(|value| !matches!(value.as_str(), "" | "0" | "false" | "off"))
            .unwrap_or(false)
    })
}

pub fn ip_run(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn ip_run_quiet(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
