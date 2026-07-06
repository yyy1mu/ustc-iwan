use super::crypto;
use base64::Engine;

fn gf128_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xE1000000000000000000000000000000;
    let mut x = x;
    let mut z = 0u128;
    for i in 0..128 {
        if (y >> (127 - i)) & 1 == 1 {
            z ^= x;
        }
        let carry = x & 1;
        x >>= 1;
        if carry == 1 {
            x ^= R;
        }
    }
    z
}

fn inc32(j: &[u8; 16]) -> [u8; 16] {
    let v = u128::from_be_bytes(*j);
    let lo = ((v & 0xFFFF_FFFF) as u32).wrapping_add(1);
    ((v >> 32) << 32 | lo as u128).to_be_bytes()
}

fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut data = Vec::with_capacity(
        aad.len() + (16 - aad.len() % 16) % 16 + ct.len() + (16 - ct.len() % 16) % 16 + 16,
    );
    data.extend_from_slice(aad);
    while data.len() % 16 != 0 {
        data.push(0);
    }
    let ct_ofs = data.len();
    data.extend_from_slice(ct);
    while (data.len() - ct_ofs) % 16 != 0 {
        data.push(0);
    }
    data.extend_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    data.extend_from_slice(&(ct.len() as u64 * 8).to_be_bytes());
    let mut y = 0u128;
    for c in data.chunks_exact(16) {
        let b: [u8; 16] = c.try_into().unwrap();
        y = gf128_mul(y ^ u128::from_be_bytes(b), h);
    }
    y
}

pub fn gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct_tag: &[u8], aad: &[u8]) -> Vec<u8> {
    assert!(ct_tag.len() >= 16, "ciphertext too short for tag");
    let (ct, tag) = ct_tag.split_at(ct_tag.len() - 16);

    let h_block = crypto::aes_block_256(key, &[0u8; 16]);
    let h = u128::from_be_bytes(h_block);

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let mut j = inc32(&j0);
    let mut plain = Vec::with_capacity(ct.len());
    for chunk in ct.chunks(16) {
        let ks = crypto::aes_block_256(key, &j);
        for (c, k) in chunk.iter().zip(ks.iter()) {
            plain.push(c ^ k);
        }
        j = inc32(&j);
    }

    let sv = crypto::aes_block_256(key, &j0);
    let s = ghash(h, aad, ct).to_be_bytes();
    let computed: Vec<u8> = s.iter().zip(sv.iter()).map(|(a, b)| a ^ b).collect();
    if computed.as_slice() != tag {
        panic!("GCM InvalidTag");
    }
    plain
}

pub fn b64url_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .unwrap_or_else(|_| panic!("base64 decode failed: {s}"))
}

pub fn b64url_no_pad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn decrypt_password(
    encrypted_b64: &str,
    app_secret: &str,
    domain: &str,
    username: &str,
) -> String {
    let label = format!("{app_secret}|{domain}|{username}");
    let key = crypto::sha256(label.as_bytes());
    let data = b64url_decode(encrypted_b64);
    assert!(data.len() >= 28, "encrypted password too short");
    let (nonce, ct_tag) = data.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let aad = format!("{domain}|{username}");
    let plain = gcm_decrypt(&key, &nonce, ct_tag, aad.as_bytes());
    String::from_utf8(plain).unwrap_or_else(|e| format!("<utf8 error: {e}>"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_padded_and_unpadded_base64url() {
        assert_eq!(
            b64url_decode("eyJzdWIiOiJTQTIzMjIxMTE0In0"),
            br#"{"sub":"SA23221114"}"#
        );
        assert_eq!(b64url_decode("aGk="), b"hi");
        assert_eq!(
            b64url_decode("SewlHBmRrTfRW2ngUX7K/7wspO/ey409480QfXmduEJ7n1rSlo4JRECcsQ==").len(),
            43
        );
    }
}
