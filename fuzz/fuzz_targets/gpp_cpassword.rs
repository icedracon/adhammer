#![no_main]
//! WS-FUZZ-6 (1.4.9) — GPP cpassword decryptor (MS14-025).
//!
//! `cpassword` is a base64-of-AES256-of-known-key blob emitted by the old
//! Group Policy Preferences UI. Operators feed cpassword strings scraped
//! from SYSVOL XML into `decrypt_cpassword` — those strings are
//! attacker-controlled in a hostile-SYSVOL scenario (a compromised DFS
//! replica serving crafted XML). Parser must survive any UTF-8 byte
//! sequence without panicking.
use libfuzzer_sys::fuzz_target;

extern crate adhammer_sysvol;

fuzz_target!(|data: &[u8]| {
    // Byte-slice → &str; skip non-UTF-8 (the real decrypt entry takes &str).
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = adhammer_sysvol::gpp::decrypt_cpassword(s);
    }
});
