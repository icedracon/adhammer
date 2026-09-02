#![no_main]
//! WS-FUZZ-CORE (1.4.10) — `adhammer_core::sanitize::sanitize_terminal_output`.
//!
//! Every string leaving the network passes through this sanitizer before
//! reaching stdout / stderr / Finding.detail / report body. It must never
//! panic on any byte pattern: hostile network peers can embed arbitrary
//! ESC / CSI / OSC / C0 shapes in LDAP attributes, GPO comments, SMB share
//! descriptions, WinRM stderr — any of which can flow into the sanitizer.
//! The fuzz target feeds arbitrary bytes (as a UTF-8 lossy `String` first,
//! since the API takes `&str`) and asserts the call returns.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // sanitize_terminal_output takes `&str`; convert lossy so we exercise
    // the full valid-UTF-8 input space (including all multibyte + C1
    // shapes). Invalid-UTF-8 bytes become U+FFFD which is what any Rust
    // caller building the input via `String::from_utf8_lossy` produces.
    let s = String::from_utf8_lossy(data);
    let _ = adhammer_core::sanitize_terminal_output(&s);
});
