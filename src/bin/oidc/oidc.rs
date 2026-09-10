use anyhow::{Context, Result};
use iwan::core::{crypto, gcm};
use rand::RngCore;
use std::io::{self, Write};

const AUTH_URL: &str = "https://auth.ivpn.ustc.edu.cn/login/oauth/authorize";
const TOKEN_URL: &str = "https://auth.ivpn.ustc.edu.cn/api/login/oauth/access_token";
const CLIENT_ID: &str = "afc6479ffb531d71daef";
const REDIRECT: &str = "com.panabit.mobile://oauth2redirect";
const SCOPE: &str = "openid profile email offline_access";

pub fn run(agent: &ureq::Agent) -> Result<(String, String)> {
    let mut vb = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut vb);
    let code_verifier = gcm::b64url_no_pad(&vb);
    let code_challenge = gcm::b64url_no_pad(&crypto::sha256(code_verifier.as_bytes()));
    let state = rand_alphanum(32);

    let auth_url = authorization_url(&code_challenge, &state)?;

    eprintln!("  Open in browser:\n  {auth_url}\n");
    let redirect = read_line("  Paste redirect URL: ");
    let parsed = url::Url::parse(&redirect).context("invalid redirect URL")?;
    let query: std::collections::HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let code = query
        .get("code")
        .context("no authorization code in redirect URL")?;

    let (st, resp) = http_post_json(
        agent,
        TOKEN_URL,
        &serde_json::json!({
            "client_id": CLIENT_ID, "code": code,
            "code_verifier": code_verifier, "redirect_uri": REDIRECT,
            "grant_type": "authorization_code",
        }),
        &[("Content-Type", "application/json")],
    )?;
    if st != 200 {
        anyhow::bail!("token exchange failed HTTP {st}: {resp}");
    }

    let kp = resp["access_token"]
        .as_str()
        .context("no access_token")?
        .to_string();
    let username = resp["id_token"]
        .as_str()
        .and_then(|jwt| jwt.split('.').nth(1))
        .and_then(|payload| {
            let claims: serde_json::Value =
                serde_json::from_slice(&gcm::b64url_decode(payload)).ok()?;
            claims["name"]
                .as_str()
                .or_else(|| claims["preferred_username"].as_str())
                .or_else(|| claims["sub"].as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".into());

    eprintln!("  Authenticated as {username}");
    Ok((kp, username))
}

fn authorization_url(code_challenge: &str, state: &str) -> Result<String> {
    let mut url = url::Url::parse(AUTH_URL).context("invalid authorization URL")?;
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT)
        .append_pair("response_type", "code")
        .append_pair("scope", SCOPE)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state);
    Ok(url.into())
}

fn rand_alphanum(len: usize) -> String {
    const CS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut r = rand::thread_rng();
    (0..len)
        .map(|_| CS[r.next_u32() as usize % CS.len()] as char)
        .collect()
}

fn read_line(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    line.trim().to_string()
}

pub(crate) fn http_post_json(
    agent: &ureq::Agent,
    url: &str,
    body: &serde_json::Value,
    headers: &[(&str, &str)],
) -> Result<(u16, serde_json::Value)> {
    let bd = serde_json::to_vec(body)?;
    let mut req = agent.post(url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.send_bytes(&bd) {
        Ok(r) => Ok((r.status(), r.into_json().unwrap_or(serde_json::Value::Null))),
        Err(ureq::Error::Status(code, r)) => Ok((
            code,
            serde_json::Value::String(r.into_string().unwrap_or_default()),
        )),
        Err(e) => anyhow::bail!("HTTP error: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_encodes_query_parameters() {
        let url = authorization_url("challenge+/=", "state 1").unwrap();
        assert!(url.starts_with(&format!("{AUTH_URL}?")));
        assert!(url.contains("client_id=afc6479ffb531d71daef"));
        assert!(url.contains("redirect_uri=com.panabit.mobile%3A%2F%2Foauth2redirect"));
        assert!(url.contains("scope=openid+profile+email+offline_access"));
        assert!(url.contains("code_challenge=challenge%2B%2F%3D"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state+1"));
    }
}
