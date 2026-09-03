#![no_main]
//! WS-FOUNDATION-DNS-HANDROLL (1.5.0) — fuzz the hand-rolled DNS response
//! parser. `parse_response` consumes bytes straight off a UDP socket from
//! a DNS server that a black-box target's environment controls (or that an
//! on-path attacker spoofs). It must never panic on any input — only
//! return `Err`. libFuzzer drives arbitrary bytes through it.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = adhammer_collector::dns_wire::parse_response(data);
});
