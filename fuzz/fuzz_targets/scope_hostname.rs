#![no_main]
//! WS-FUZZ-CORE (1.4.10) — `adhammer_core::EngagementScope` JSON round-trip.
//!
//! Runners load an EngagementScope from an operator-supplied JSON file
//! (planned WS-FOUNDATION-BLACKBOX-CLI, 1.5.0). Exercise the deserialize
//! + validate + allows path with arbitrary UTF-8 bytes cast as JSON — the
//! parser + hostname normalizer must never panic on any byte pattern,
//! only return an `Err`.
use adhammer_core::EngagementScope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = std::str::from_utf8(data);
    let Ok(s) = s else { return };
    // JSON deserialize is fallible + must not panic. If it succeeds, run
    // validate() and both allows() axes — those touch `normalize_name`,
    // the ScopeTarget matchers, and the excludes-cross-cutting logic.
    if let Ok(scope) = serde_json::from_str::<EngagementScope>(s) {
        let _ = scope.validate();
        // ip axis
        let _ = scope.allows_ip("127.0.0.1".parse().unwrap());
        let _ = scope.allows_ip("::1".parse().unwrap());
        // hostname axis: run with arbitrary borrowed data so the
        // normalizer's byte-level accept path takes arbitrary input.
        let _ = scope.allows_hostname("dc01.corp.local");
        let _ = scope.allows_hostname(s);
    }
});
