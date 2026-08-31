#![no_main]
//! WS-FUZZ-6 (1.4.9) — PAC container walk via `decrypt_and_parse_credential_info`.
//!
//! Exercises the deeper NDR-parse path for `PAC_CREDENTIAL_DATA` after
//! notional decrypt. Fuzz input is the *plaintext* that would follow
//! decrypt — this is the shape a hostile plaintext (which could reach
//! us if a downgraded/broken KDC returned garbage-encrypted-with-a-
//! known-key material) would take. The NDR walk must not panic on any
//! sequence of bytes.
//!
//! Note the etype=18 argument mirrors real Server 2025 AS-REP shape;
//! decrypt will fail on random bytes, but the shape of the failure
//! path is what we're checking doesn't crash.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let session_key = [0u8; 32];
    let _ = adhammer_kerberos::unpac::decrypt_and_parse_credential_info(data, &session_key);
});
