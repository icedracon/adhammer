//! Process-global speed mode.
//!
//! ADhammer paces a few operations on purpose so the default experience is
//! friendly and forgiving on slow or loaded hosts — most visibly the WMI
//! command-output read-back backoff (up to ~8s per `wmiexec`) and the
//! conservative per-port connect timeouts in the network sweep.
//!
//! An operator on a fast, authorized network who wants raw throughput can opt
//! into **native speed** with the global `--fast` flag (or `ADHAMMER_FAST=1`),
//! which collapses that deliberate pacing.
//!
//! Native speed touches ONLY artificial pacing. Safety controls that exist to
//! protect the *target* — e.g. the password-spray lockout window — are never
//! altered by this switch.

use std::sync::atomic::{AtomicBool, Ordering};

static NATIVE: AtomicBool = AtomicBool::new(false);

/// Enable (or disable) native speed. Call once at startup, after arg parsing.
pub fn set_native(on: bool) {
    NATIVE.store(on, Ordering::Relaxed);
}

/// True when the operator asked for native speed (`--fast` / `ADHAMMER_FAST`).
/// Pacing/backoff sites collapse their deliberate delays when this is set.
pub fn is_native() -> bool {
    NATIVE.load(Ordering::Relaxed)
}

/// Pick the `safe` value by default, or the `native` value under `--fast`.
/// Keeps call sites terse:
/// `let t = speed::pick(Duration::from_millis(1200), Duration::from_millis(400));`
pub fn pick<T>(safe: T, native: T) -> T {
    if is_native() {
        native
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_safe_and_toggles() {
        // Default (nothing set in this test process yet for these asserts).
        set_native(false);
        assert!(!is_native());
        assert_eq!(pick("safe", "native"), "safe");
        set_native(true);
        assert!(is_native());
        assert_eq!(pick("safe", "native"), "native");
        // restore so we don't leak state into sibling tests in the same binary
        set_native(false);
    }
}
