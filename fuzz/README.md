# Fuzzing ADhammer's wire parsers

The hand-rolled parsers that consume attacker-influenced bytes are fuzzed two ways.

## 1. `cargo test` fuzz-lite (runs everywhere, incl. Windows/CI)

Each risky parser has a deterministic, seeded `catch_unwind` harness inside its crate's tests —
200k random + seed-mutated inputs per parser, asserting no panic. Runs on stable with the normal
suite:

```sh
cargo test --workspace
```

Targets: `sddl::parse` (SD/DACL/ACE), `secrets::hive` (regf), `dcerpc::epm` +
`dcerpc::drsuapi::parse_repl_object` (DC replies), `ldap::read_tlv` (BER), and the CLI network
parsers (`snmp_first_octet_string`, `parse_exports`, `parse_prelogin`).

These already caught real bugs: an out-of-bounds slice in the object-ACE path of `sddl::parse`
and a `pos + hdr + len` integer overflow in `ldap::read_tlv` on a crafted long-form length.

## 2. cargo-fuzz / libFuzzer (nightly, Linux — the Kali deploy target)

Coverage-guided fuzzing of the public parsers. **Not run in the Windows dev environment** (no
libFuzzer there); run on Kali/Linux:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run sddl_parse     # or hive_parse, epm_decode
cargo +nightly fuzz run sddl_parse -- -max_total_time=300
```

Targets: `sddl_parse`, `hive_parse`, `epm_decode`. Add a target by dropping a
`fuzz_targets/<name>.rs` and a matching `[[bin]]` in `Cargo.toml`.
