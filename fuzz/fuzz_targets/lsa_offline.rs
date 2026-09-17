#![no_main]
//! Fuzz the offline SAM/LSA secret parsers (`adhammer-secrets`) — the byte-eating
//! path behind `attack secretsdump ... LOCAL` and offline `lsa` dumping. The
//! SYSTEM / SAM / SECURITY hives are pulled from a target or a backup, so a
//! corrupt or hostile pair must return `Err` — never panic or over-allocate.
//!
//! Closes the audit's "lsa_offline unverified" fuzz gap (the SAM/LSA decrypt
//! chain, beyond the raw regf `hive_parse` target). Feeds two independently
//! varied slices so the bootkey-source hive and the secret hive both mutate.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let (system, other) = data.split_at(split);
    // SAM path: SYSTEM hive (bootkey) + SAM hive -> per-user NT hashes.
    let _ = adhammer_secrets::local_dump(system, other);
    // LSA path: SYSTEM hive (bootkey) + SECURITY hive -> LSA secrets / DCC2.
    let _ = adhammer_secrets::local_lsa(system, other);
});
