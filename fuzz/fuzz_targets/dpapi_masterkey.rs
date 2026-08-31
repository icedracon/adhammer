#![no_main]
//! WS-FUZZ-6 (1.4.9) — DPAPI masterkey-file parser + subfield-header decode.
//!
//! Masterkey files come from `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` on
//! the target host. When the operator hands one to `attack
//! dpapi-master-key`, the parser must survive any 400-1000-byte input
//! without panic — even a file that's been intentionally truncated,
//! zero-filled, or crafted to overflow the `MasterKeyLen` / `BackupKeyLen`
//! / `CredHistLen` / `DomainKeyLen` u64 length fields.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mkf) = dpapi_offline::MasterKeyFile::parse(data) {
        // If parse succeeded, subfield header decoded — attempt a decrypt
        // with a zeroed pwdkey. Decrypt will fail HMAC-verify; success
        // here means the ms_derive_key + AES-CBC path handled every
        // path without panic.
        if let Some(mk) = mkf.master_key {
            let pwdkey = [0u8; 20];
            let _ = mk.decrypt_with_key(&pwdkey);
        }
    }
});
