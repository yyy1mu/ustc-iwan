use anyhow::Result;
use iwan::core::crypto;
use rand::RngCore;

const CONTROLLER: &str = "https://crtl.ivpn.ustc.edu.cn";
const APP_ID: &str = "controller-ustc";
const APP_SECRET: &str = "ca6a3532abd2986a03b86b3a";

pub fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().build()
}

pub fn post(
    agent: &ureq::Agent,
    path: &str,
    body: &serde_json::Value,
    kp_token: &str,
) -> Result<(u16, serde_json::Value)> {
    let ts = format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let nonce = nonce_hex();
    let bd = serde_json::to_vec(body)?;
    let canonical = format!(
        "POST\n{path}\n\n{}\n{ts}\n{nonce}",
        crypto::hex(&crypto::sha256(&bd))
    );
    let sig = crypto::hex(&crypto::hmac_sha256(
        APP_SECRET.as_bytes(),
        canonical.as_bytes(),
    ));

    super::oidc::http_post_json(
        agent,
        &format!("{CONTROLLER}{path}"),
        body,
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &format!("Bearer {kp_token}")),
            ("X-Auth-AppId", APP_ID),
            ("X-Auth-Timestamp", &ts),
            ("X-Auth-Nonce", &nonce),
            ("X-Auth-Sign", &sig),
        ],
    )
}

fn nonce_hex() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    crypto::hex(&b).to_uppercase()
}
