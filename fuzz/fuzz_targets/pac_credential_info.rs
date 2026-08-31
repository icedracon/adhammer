#![no_main]
//! WS-FUZZ-6 (1.4.9) — `PAC_CREDENTIAL_INFO` buffer decoder.
//!
//! The PAC container comes from a KDC AS-REP / TGS-REP. A hostile KDC (or
//! a Samba-honeypot / random-TCP-listener the operator aimed the tool at)
//! sends attacker-controlled bytes to this parser. It must not panic on
//! any input: not on malformed `Offset` fields that would overflow the
//! bounds check, not on `cbBufferSize` claims larger than the message,
//! not on truncated buffer bodies, not on `EncryptionType` values that
//! aren't 17/18/23.
//!
//! Session key is a zeroed 32-byte AES256-shape key — decrypt will fail
//! but the *parse-and-validate* path is what we're exercising. Success
//! means the function returned Err cleanly, not that the credentials
//! were extracted.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let session_key = [0u8; 32];
    let _ = adhammer_kerberos::unpac::unpac_credential_info(data, &session_key);
});
