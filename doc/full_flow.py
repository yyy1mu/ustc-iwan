#!/usr/bin/env python3
"""
iWAN 全自动凭证提取 — 完整版 (含密码解密)

用法: python3 full_flow.py
"""
import base64, hashlib, hmac, json, secrets, ssl, struct, sys, time
import urllib.parse
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ═══════════════════ 配置 ═══════════════════
ISSUER      = "https://auth.ivpn.ustc.edu.cn"
AUTH_URL    = f"{ISSUER}/login/oauth/authorize"
TOKEN_URL   = f"{ISSUER}/api/login/oauth/access_token"
CLIENT_ID   = "afc6479ffb531d71daef"
REDIRECT    = "com.panabit.mobile://oauth2redirect"
SCOPE       = "openid profile email offline_access"
DOMAIN      = "iwan.ustc"
CONTROLLER  = "https://crtl.ivpn.ustc.edu.cn"
APP_ID      = "controller-ustc"
APP_SECRET  = "ca6a3532abd2986a03b86b3a"
DEVICE_ID   = secrets.token_hex(8)
OUT_FILE    = "iwan_credentials.json"

ctx = ssl.create_default_context()
ctx.check_hostname = ctx.verify_mode = False

# ═══════════════════ AES-GCM 解密 ═══════════════════

def gf128_mul(x, y):
    R = 0xE1000000000000000000000000000000
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1: z ^= x
        carry = x & 1; x >>= 1
        if carry: x ^= R
    return z

def aes_block(key, block):
    c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return c.update(block) + c.finalize()

def gcm_decrypt(key, nonce_12b, ct_tag, aad=b''):
    L = len(ct_tag) - 16
    if L < 0: raise ValueError("too short")
    tag = ct_tag[-16:]; ct = ct_tag[:L]
    J0 = nonce_12b + b'\x00\x00\x00\x01'
    H = aes_block(key, b'\x00'*16)
    def inc32(j):
        v = int.from_bytes(j, 'big')
        return ((v>>32)<<32 | ((v&0xFFFFFFFF)+1)&0xFFFFFFFF).to_bytes(16,'big')
    J = inc32(J0); plain = b''
    for i in range(0, L, 16):
        S = aes_block(key, J)
        plain += bytes(a^c for a,c in zip(ct[i:i+16], S[:len(ct[i:i+16])]))
        J = inc32(J)
    al, cl = len(aad)*8, L*8
    ghin = aad+b'\x00'*((16-len(aad)%16)%16)+ct+b'\x00'*((16-L%16)%16)
    ghin += struct.pack('>Q',al)+struct.pack('>Q',cl)
    H_int = int.from_bytes(H,'big'); S = 0
    for i in range(0, len(ghin), 16):
        S ^= int.from_bytes(ghin[i:i+16],'big')
        S = gf128_mul(S, H_int)
    comp = int.to_bytes(S^int.from_bytes(aes_block(key,J0),'big'),16,'big')
    if comp != tag: raise ValueError("InvalidTag")
    return plain

def decrypt_password(encrypted_b64, domain, username):
    """解密 iWAN 服务器密码"""
    s = encrypted_b64.replace('-','+').replace('_','/')
    s += '='*((4-len(s)%4)%4)
    data = base64.b64decode(s)
    if len(data) < 28: raise ValueError("too short")
    key = hashlib.sha256(f"{APP_SECRET}|{domain}|{username}".encode()).digest()
    return gcm_decrypt(key, data[:12], data[12:], f"{domain}|{username}".encode()).decode()

# ═══════════════════ 认证工具 ═══════════════════

def build_canonical(method, path, body_bytes, ts, nonce):
    body_sha = hashlib.sha256(body_bytes).hexdigest()
    return f"{method}\n{path}\n\n{body_sha}\n{ts}\n{nonce}"

def sign(canonical, key):
    return hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()

def http_post(url, body_dict, headers):
    data = json.dumps(body_dict).encode() if body_dict else b"{}"
    req = Request(url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=15, context=ctx) as r:
            return r.status, json.loads(r.read())
    except Exception as e:
        code = getattr(e, "code", 0)
        body = getattr(e, "read", lambda: b"")()[:300].decode(errors="replace")
        return code, body

def ctrl_post(path, body, kp_token):
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16).upper()
    bd = json.dumps(body).encode()
    canonical = build_canonical("POST", path, bd, ts, nonce)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {kp_token}",
        "X-Auth-AppId": APP_ID,
        "X-Auth-Timestamp": ts,
        "X-Auth-Nonce": nonce,
        "X-Auth-Sign": sign(canonical, APP_SECRET),
    }
    url = urllib.parse.urljoin(CONTROLLER, path)
    return http_post(url, body, headers)

# ═══════════════════ 流程 ═══════════════════

def sso_login():
    code_verifier = secrets.token_urlsafe(64)[:128]
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    params = urllib.parse.urlencode({
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
        "response_type": "code", "scope": SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": secrets.token_hex(16),
    })

    print(f"     浏览器: {AUTH_URL}?{params}\n")
    redirect_uri = input("     粘贴完整跳转 URL: ").strip()
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(redirect_uri).query)
    code = qs.get("code", [None])[0]
    if not code:
        raise RuntimeError("未找到 authorization code")

    token_data = json.dumps({
        "client_id": CLIENT_ID, "code": code,
        "code_verifier": code_verifier, "redirect_uri": REDIRECT,
        "grant_type": "authorization_code",
    }).encode()
    req = Request(TOKEN_URL, data=token_data,
                  headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=15, context=ctx) as r:
        resp = json.loads(r.read())

    kp = resp.get("access_token")
    if not kp:
        raise RuntimeError(f"Token 交换失败: {json.dumps(resp, indent=2)}")

    username = ""
    try:
        raw = resp.get("id_token", "").split(".")[1]
        raw += "=" * (4 - len(raw) % 4)
        jwt = json.loads(base64.urlsafe_b64decode(raw))
        username = jwt.get("name") or jwt.get("preferred_username") or jwt.get("sub", "")
    except: pass

    print(f"     ✅ {username} | {kp[:50]}...")
    return kp, username


def main():
    print(f"  iWAN 凭证提取 | device_id={DEVICE_ID}\n")

    kp, uname = sso_login()

    body = {
        "domain": DOMAIN, "type": "android", "oem_name": "panabit",
        "device_id": DEVICE_ID, "userName": uname,
        "serverlist_version": "0", "ipfilter_version": "0", "branding_version": "0",
    }

    print("  ② /m/auth...", end=" ", flush=True)
    st, resp = ctrl_post("/m/auth", body, kp)
    if st != 200: raise RuntimeError(f"失败 HTTP {st}: {resp}")
    print(f"✅ {resp.get('auth',{}).get('oidc',{}).get('issuer','?')}")

    print("  ③ /m/keepalive...", end=" ", flush=True)
    kp_body = dict(body); kp_body["type"] = "keepalive"
    st, _ = ctrl_post("/m/keepalive", kp_body, kp)
    print(f"HTTP {st}")

    print("  ④ /m/config...", end=" ", flush=True)
    st, resp = ctrl_post("/m/config", body, kp)
    if st != 200: raise RuntimeError(f"失败 HTTP {st}: {resp}")

    sl = resp.get("serverlist", {}).get("serverlist", [])
    servers = []
    for s in sl:
        encrypted_pw = s.get("passWord", "")
        server_user = s.get("userName", "")  # 服务器配置里的 userName
        try:
            password = decrypt_password(encrypted_pw, DOMAIN, server_user)
        except Exception as e:
            password = f"<解密失败: {e}>"
        servers.append({
            "name": s.get("name", ""),
            "host": s.get("serverName", ""),
            "port": s.get("serverPort", 0),
            "username": s.get("userName", ""),
            "password": password,
        })
    print(json.dumps(servers, indent=2, ensure_ascii=False))
    with open(OUT_FILE, "w") as f:
        json.dump({"domain": DOMAIN, "servers": servers}, f, indent=2, ensure_ascii=False)
    print(f"\n✅ {OUT_FILE}")


if __name__ == "__main__":
    main()
