#![no_main]
//! Fuzz the registry-hive (regf) parser + navigation — hives are retrieved from targets, so a
//! corrupt/hostile one must not panic the offline secrets dumper.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(h) = adhammer_secrets::Hive::parse(data.to_vec()) {
        let _ = h.is_valid();
        let _ = h.subkey_names("SAM\\Domains\\Account\\Users");
        let _ = h.value("SAM\\Domains\\Account", "F");
        let _ = h.key_class("ControlSet001\\Control\\Lsa\\JD");
        let _ = h.value_u32("Select", "Current");
    }
});
