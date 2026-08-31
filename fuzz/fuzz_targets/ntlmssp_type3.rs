#![no_main]
//! WS-FUZZ-6 (1.4.9) — NTLMSSP Type3 crack-hash extractor.
//!
//! `netntlmv2_from_type3` is what `attack capture` runs on every incoming
//! Type3 auth message it receives on the SMB listener. Client-controlled
//! bytes reach the parser; must never panic on any input, no matter how
//! malformed the Type3 shape is.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let server_challenge = [0u8; 8];
    let _ = ntlmssp::netntlmv2_from_type3(data, &server_challenge);
});
