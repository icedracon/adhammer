#![no_main]
//! WS-FUZZ-6 (1.4.9) — NTLMSSP Type2 challenge parser.
//!
//! Every SMB / LDAP / WinRM auth handshake we perform reads a Type2
//! challenge message from the server. A hostile / compromised server can
//! ship arbitrary bytes there; the parser must never panic. The bug class
//! is the same as BUG-15..18: bad length fields, out-of-range offsets,
//! integer-overflow wraparound before the bounds check.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ntlmssp::parse_challenge(data);
});
