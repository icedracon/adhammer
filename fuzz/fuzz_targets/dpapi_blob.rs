#![no_main]
//! WS-FUZZ-6 (1.4.9) — DPAPI blob parser.
//!
//! A `CryptProtectData` output blob is what you find in Chrome cookie
//! store, Wi-Fi profile XML, RDP saved credentials — all files the
//! operator may hand to this parser after lifting them off a target
//! host. The bytes are therefore attacker-controlled at parse time.
//!
//! We exercise the pre-decrypt parse only (no masterkey needed to
//! reach the parser); a hostile blob must not panic here.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dpapi_offline::DpapiBlob::parse(data);
});
