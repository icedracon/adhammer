//! RC4-HMAC (etype 23, RFC 4757 / MS-KILE) — the legacy Kerberos cipher picky-krb doesn't
//! implement. Its string-to-key is simply the NT hash (`MD4(UTF-16LE(password))`), which is what
//! makes **overpass-the-hash** possible: a captured NT hash *is* the Kerberos key. Server
//! 2016–2022 enable RC4 by default; 2025 disables it.
//!
//! encrypt(K, usage, P):  Ki = HMAC-MD5(K, T);  data = confounder(8) || P;
//!                        cksum = HMAC-MD5(Ki, data);  Ke = HMAC-MD5(Ki, cksum);
//!                        output = cksum || RC4(Ke, data)
//! where T is the (MS-remapped) key usage as a 4-byte LE integer.

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// RC4-HMAC string-to-key: the NT hash, `MD4(UTF-16LE(password))`.
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut md4 = Md4::new();
    for u in password.encode_utf16() {
        md4.update(u.to_le_bytes());
    }
    md4.finalize().into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = <HmacMd5 as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Hand-rolled RC4 keystream (RFC 6229); keys here are always the 16-byte HMAC-MD5 output.
fn rc4_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    data.iter()
        .map(|&b| {
            i = (i + 1) & 0xff;
            j = (j + s[i] as usize) & 0xff;
            s.swap(i, j);
            b ^ s[(s[i] as usize + s[j] as usize) & 0xff]
        })
        .collect()
}

/// MS-KILE key-usage remapping for RC4-HMAC (RFC 4757 §3): a few usages are aliased.
fn usage_t(usage: i32) -> [u8; 4] {
    let ms = match usage {
        3 => 8,   // AS-REP enc-part
        9 => 8,   // TGS-REP enc-part (subkey)
        23 => 13, // (per RFC 4757)
        u => u,
    };
    (ms as u32).to_le_bytes()
}

/// RC4-HMAC encrypt. `confounder` is 8 bytes (pass `None` for random).
pub fn encrypt(key: &[u8], usage: i32, plaintext: &[u8], confounder: Option<[u8; 8]>) -> Vec<u8> {
    let conf = confounder.unwrap_or_else(|| {
        let mut c = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut c);
        c
    });
    let ki = hmac_md5(key, &usage_t(usage));
    let mut data = conf.to_vec();
    data.extend_from_slice(plaintext);
    let cksum = hmac_md5(&ki, &data);
    let ke = hmac_md5(&ki, &cksum);
    let mut out = cksum.to_vec();
    out.extend_from_slice(&rc4_apply(&ke, &data));
    out
}

/// RC4-HMAC decrypt. Verifies the HMAC checksum; returns the plaintext (confounder stripped).
pub fn decrypt(key: &[u8], usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.len() < 16 + 8 {
        return Err("RC4-HMAC ciphertext too short");
    }
    let (cksum, enc) = ciphertext.split_at(16);
    let ki = hmac_md5(key, &usage_t(usage));
    let ke = hmac_md5(&ki, cksum);
    let data = rc4_apply(&ke, enc);
    if hmac_md5(&ki, &data) != cksum {
        return Err("RC4-HMAC checksum mismatch (wrong key)");
    }
    Ok(data[8..].to_vec()) // strip the 8-byte confounder
}

/// KERB_CHECKSUM_HMAC_MD5 (checksum type -138, RFC 4757 §4) — the PAC signature algorithm that
/// pairs with an RC4 key: `Ksign = HMAC-MD5(K, "signaturekey\0"); HMAC-MD5(Ksign, MD5(LE32(usage) || data))`.
/// 16-byte output. Used for RC4 golden/silver PAC server+KDC signatures.
pub fn hmac_md5_checksum(key: &[u8], usage: i32, data: &[u8]) -> [u8; 16] {
    let ksign = hmac_md5(key, b"signaturekey\0");
    let mut md5 = Md5::new();
    md5.update(usage.to_le_bytes());
    md5.update(data);
    let tmp = md5.finalize();
    hmac_md5(&ksign, &tmp)
}

/// SignatureType for the PAC checksum buffers when signing with an RC4 key.
pub const SIG_HMAC_MD5: i32 = -138;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_md5_checksum_is_16_and_deterministic() {
        let k = nt_hash("k");
        let a = hmac_md5_checksum(&k, 17, b"pac-bytes");
        assert_eq!(a.len(), 16);
        assert_eq!(a, hmac_md5_checksum(&k, 17, b"pac-bytes"));
        assert_ne!(a, hmac_md5_checksum(&k, 17, b"pac-bytez"));
    }

    #[test]
    fn nt_hash_known_vector() {
        // NT hash of "password" (MS-NLMP / widely published).
        assert_eq!(
            hex::encode(nt_hash("password")),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = nt_hash("Passw0rd!");
        for usage in [1i32, 2, 3, 7, 8, 9, 11, 23] {
            let pt = b"the quick brown fox jumps over the lazy DC";
            let ct = encrypt(&key, usage, pt, None);
            // checksum(16) + confounder(8) + plaintext
            assert_eq!(ct.len(), 16 + 8 + pt.len());
            assert_eq!(decrypt(&key, usage, &ct).unwrap(), pt);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt(&nt_hash("right"), 8, b"secret", None);
        assert!(decrypt(&nt_hash("wrong"), 8, &ct).is_err());
    }

    #[test]
    fn deterministic_with_fixed_confounder() {
        // Same key/usage/confounder ⇒ identical output (crypto is wired deterministically).
        let key = nt_hash("k");
        let c = [0x11u8; 8];
        assert_eq!(
            encrypt(&key, 1, b"abc", Some(c)),
            encrypt(&key, 1, b"abc", Some(c))
        );
    }
}
