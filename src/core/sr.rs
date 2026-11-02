use aes::{Aes128, Aes256};
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrKeyMode {
    /// Linux client: srpassword + jhash(srlinks) + jhash(reversed links)
    Jhash,
    /// Android SR group: raw ingress password bytes (AES-128/256 key).
    Raw,
}

impl SrKeyMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "raw" | "android" => Some(Self::Raw),
            "jhash" | "linux" | "" => Some(Self::Jhash),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SrConfig {
    pub password: String,
    pub links: Vec<u32>,
    /// 1 = AES-128, 2 = AES-256 (matching the client's srencryptmode).
    pub mode: u8,
    pub key_mode: SrKeyMode,
    pub local_id: u32,
}

impl SrConfig {
    pub fn from_options(
        password: &str,
        links: &[u32],
        mode: u8,
        key_mode: SrKeyMode,
    ) -> Option<Self> {
        if mode == 0 && links.is_empty() {
            return None;
        }
        Some(Self {
            password: password.to_string(),
            links: if links.is_empty() {
                vec![1]
            } else {
                links.to_vec()
            },
            mode,
            key_mode,
            local_id: 0,
        })
    }

    pub fn with_local_id(mut self, local_id: u32) -> Self {
        self.local_id = local_id;
        self
    }

    pub fn enabled(&self) -> bool {
        !self.links.is_empty()
    }

    pub fn key(&self) -> Vec<u8> {
        let key_len = if self.mode == 1 { 16 } else { 32 };
        if self.key_mode == SrKeyMode::Raw {
            let mut key = [0u8; 32];
            let raw = self.password.as_bytes();
            let n = raw.len().min(key_len);
            key[..n].copy_from_slice(&raw[..n]);
            return key[..key_len].to_vec();
        }
        let mut hash = 0u32;
        if !self.links.is_empty() {
            let mut links_be = Vec::with_capacity(self.links.len() * 4);
            for link in &self.links {
                links_be.extend_from_slice(&link.to_be_bytes());
            }
            let forward = jhash(&links_be, links_be.len() as u32, 0);
            let mut reversed = Vec::with_capacity(links_be.len());
            for link in self.links.iter().rev() {
                reversed.extend_from_slice(&link.to_be_bytes());
            }
            hash = forward.wrapping_add(jhash(&reversed, reversed.len() as u32, 0));
        }

        let mut userkey = [0u8; 40];
        let pass = self.password.as_bytes();
        let n = pass.len().min(32);
        userkey[..n].copy_from_slice(&pass[..n]);
        let mut len = n;
        let mut h = hash;
        while len <= 28 {
            userkey[len..len + 4].copy_from_slice(&h.to_le_bytes());
            len += 4;
        }
        while len <= 31 {
            userkey[len] = h as u8;
            len += 1;
            h >>= 8;
        }
        userkey[..key_len].to_vec()
    }

    pub fn encrypt(&self, data: &mut [u8]) -> Result<(), String> {
        if !data.len().is_multiple_of(16) {
            return Err("SR payload is not 16-byte aligned".into());
        }
        let key = self.key();
        if key.len() == 16 {
            let cipher = Aes128::new(GenericArray::from_slice(&key));
            for chunk in data.chunks_exact_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        } else {
            let cipher = Aes256::new(GenericArray::from_slice(&key));
            for chunk in data.chunks_exact_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        Ok(())
    }

    pub fn decrypt(&self, data: &mut [u8]) -> Result<(), String> {
        if !data.len().is_multiple_of(16) {
            return Err("SR payload is not 16-byte aligned".into());
        }
        let key = self.key();
        if key.len() == 16 {
            let cipher = Aes128::new(GenericArray::from_slice(&key));
            for chunk in data.chunks_exact_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        } else {
            let cipher = Aes256::new(GenericArray::from_slice(&key));
            for chunk in data.chunks_exact_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }
        Ok(())
    }
}

/// Android's 40-byte SR monitor payload: 20-byte timing block, "SRID"+id,
/// then the 12-byte SrmonPkt (little-endian counters).
pub fn monitor_payload(local_id: u32, tx_count: u32, rx_count: u32) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[20..24].copy_from_slice(b"SRID");
    out[24..28].copy_from_slice(&local_id.to_be_bytes());
    out[28] = 0; // version
    out[29] = 121; // pad
    out[30..32].copy_from_slice(&0u16.to_le_bytes()); // flags
    out[32..36].copy_from_slice(&tx_count.to_le_bytes());
    out[36..40].copy_from_slice(&rx_count.to_le_bytes());
    out
}

/// The client's jhash (ipe_jhash.h), not Linux lookup3. The SR key is
/// derived from jhash(srlinks) + jhash(reversed srlinks), so this must match
/// the C implementation byte-for-byte.
pub fn jhash(key: &[u8], length: u32, initval: u32) -> u32 {
    let mut a = 0x9e37_79b9u32;
    let mut b = 0x9e37_79b9u32;
    let mut c = initval;
    let mut len = length;
    let mut k = key;

    while len > 11 {
        let ba = ((k[6] as u32) << 16)
            .wrapping_add(k[4] as u32)
            .wrapping_add((k[5] as u32) << 8)
            .wrapping_add((k[7] as u32) << 24)
            .wrapping_add(b);
        let cb = ((k[10] as u32) << 16)
            .wrapping_add(k[8] as u32)
            .wrapping_add((k[9] as u32) << 8)
            .wrapping_add((k[11] as u32) << 24)
            .wrapping_add(c);
        let aa = (cb >> 13)
            ^ ((k[2] as u32) << 16)
                .wrapping_add(k[0] as u32)
                .wrapping_add((k[1] as u32) << 8)
                .wrapping_add((k[3] as u32) << 24)
                .wrapping_add(a)
                .wrapping_sub(ba)
                .wrapping_sub(cb);
        let bb = (aa << 8) ^ ba.wrapping_sub(cb).wrapping_sub(aa);
        let cc = (bb >> 13) ^ cb.wrapping_sub(aa).wrapping_sub(bb);
        let ab = (cc >> 12) ^ aa.wrapping_sub(bb).wrapping_sub(cc);
        let bc = (ab << 16) ^ bb.wrapping_sub(cc).wrapping_sub(ab);
        let cd = (bc >> 5) ^ cc.wrapping_sub(ab).wrapping_sub(bc);
        a = (cd >> 3) ^ ab.wrapping_sub(bc).wrapping_sub(cd);
        b = (a << 10) ^ bc.wrapping_sub(cd).wrapping_sub(a);
        c = (b >> 15) ^ cd.wrapping_sub(a).wrapping_sub(b);
        k = &k[12..];
        len -= 12;
    }

    let mut ca = length.wrapping_add(c);
    match len {
        11 => {
            ca = ca.wrapping_add((k[10] as u32) << 24);
            ca = ca.wrapping_add((k[9] as u32) << 16);
            ca = ca.wrapping_add((k[8] as u32) << 8);
            b = b.wrapping_add((k[7] as u32) << 24);
            b = b.wrapping_add((k[6] as u32) << 16);
            b = b.wrapping_add((k[5] as u32) << 8);
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        10 => {
            ca = ca.wrapping_add((k[9] as u32) << 16);
            ca = ca.wrapping_add((k[8] as u32) << 8);
            b = b.wrapping_add((k[7] as u32) << 24);
            b = b.wrapping_add((k[6] as u32) << 16);
            b = b.wrapping_add((k[5] as u32) << 8);
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        9 => {
            ca = ca.wrapping_add((k[8] as u32) << 8);
            b = b.wrapping_add((k[7] as u32) << 24);
            b = b.wrapping_add((k[6] as u32) << 16);
            b = b.wrapping_add((k[5] as u32) << 8);
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        8 => {
            b = b.wrapping_add((k[7] as u32) << 24);
            b = b.wrapping_add((k[6] as u32) << 16);
            b = b.wrapping_add((k[5] as u32) << 8);
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        7 => {
            b = b.wrapping_add((k[6] as u32) << 16);
            b = b.wrapping_add((k[5] as u32) << 8);
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        6 => {
            b = b.wrapping_add((k[5] as u32) << 8);
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        5 => {
            b = b.wrapping_add(k[4] as u32);
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        4 => {
            a = a.wrapping_add((k[3] as u32) << 24);
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        3 => {
            a = a.wrapping_add((k[2] as u32) << 16);
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        2 => {
            a = a.wrapping_add((k[1] as u32) << 8);
            a = a.wrapping_add(k[0] as u32);
        }
        1 => {
            a = a.wrapping_add(k[0] as u32);
        }
        _ => {}
    }

    let ac = (ca >> 13) ^ a.wrapping_sub(b).wrapping_sub(ca);
    let bd = (ac << 8) ^ b.wrapping_sub(ca).wrapping_sub(ac);
    let ce = (bd >> 13) ^ ca.wrapping_sub(ac).wrapping_sub(bd);
    let ad = (ce >> 12) ^ ac.wrapping_sub(bd).wrapping_sub(ce);
    let be = (ad << 16) ^ bd.wrapping_sub(ce).wrapping_sub(ad);
    let cf = (be >> 5) ^ ce.wrapping_sub(ad).wrapping_sub(be);
    let ae = (cf >> 3) ^ ad.wrapping_sub(be).wrapping_sub(cf);
    let x = (ae << 10) ^ be.wrapping_sub(cf).wrapping_sub(ae);
    (x >> 15) ^ cf.wrapping_sub(ae).wrapping_sub(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jhash_matches_client_reference() {
        assert_eq!(jhash(&[0, 0, 0, 1], 4, 0), 0xaf94_8ed6);
        assert_eq!(jhash(&[0, 0, 0, 2, 0, 0, 0, 1], 8, 0), 0xec50_5b9c);
    }
}
