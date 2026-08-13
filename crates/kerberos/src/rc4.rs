//! RC4-HMAC (etype 23, RFC 4757 / MS-KILE) — re-exports over `ms_pac_forge::checksum`.
//!
//! Rationale: `ms-pac-forge` on crates.io ships the same RC4-HMAC primitives (its
//! `checksum.rs` was lifted from this file during the extraction). To keep a single
//! source of truth this module is now a thin shim; adhammer's `pac` / `tgs` call
//! sites (`crate::rc4::nt_hash`, `encrypt`, `decrypt`, `hmac_md5_checksum`,
//! `SIG_HMAC_MD5`) continue to work unchanged.
//!
//! Naming difference: `ms-pac-forge` uses `rc4_encrypt` / `rc4_decrypt`; this shim
//! keeps the old `encrypt` / `decrypt` names as thin wrappers so existing consumers
//! do not need to change.

pub use ms_pac_forge::checksum::{hmac_md5_checksum, nt_hash, SIG_HMAC_MD5};

/// RC4-HMAC encrypt (etype 23). Delegates to [`ms_pac_forge::checksum::rc4_encrypt`].
pub fn encrypt(key: &[u8], usage: i32, plaintext: &[u8], confounder: Option<[u8; 8]>) -> Vec<u8> {
    ms_pac_forge::checksum::rc4_encrypt(key, usage, plaintext, confounder)
}

/// RC4-HMAC decrypt (etype 23). Delegates to [`ms_pac_forge::checksum::rc4_decrypt`].
pub fn decrypt(key: &[u8], usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    ms_pac_forge::checksum::rc4_decrypt(key, usage, ciphertext)
}
