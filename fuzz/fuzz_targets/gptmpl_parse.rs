#![no_main]
//! WS-FUZZ-6 (1.4.9) — GptTmpl.inf policy parser.
//!
//! `GptTmpl.inf` files live under SYSVOL and are ini-style Windows policy
//! templates. A hostile DFS replica or a poisoned SYSVOL share can serve
//! arbitrary bytes; the parser must degrade cleanly on any UTF-8 input.
use libfuzzer_sys::fuzz_target;

extern crate adhammer_sysvol;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = adhammer_sysvol::gptmpl::parse_registry_values(s);
    }
});
