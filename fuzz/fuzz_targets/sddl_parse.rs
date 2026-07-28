#![no_main]
//! Fuzz the self-rolled SECURITY_DESCRIPTOR/DACL/ACE parser — it eats attacker-influenced
//! nTSecurityDescriptor bytes from LDAP. Must never panic on malformed input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = adhammer_sddl::parse(data);
});
