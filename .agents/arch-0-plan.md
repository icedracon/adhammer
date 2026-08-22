# arch-0 — main.rs god-file split

**Trigger:** 1.3.10 boss review flagged `cli/src/main.rs` at 5564 lines with 71 async handler fns as the single largest code smell in the tree. Every new WS adds 200-500 lines to it; splitting now unblocks the 1.4.1 feature stretch cleanly.

**Scope:** cli-internal module refactor. Zero user-visible change, zero wire-format change, zero API break for downstream consumers of published crates.

## Structure decision

**Option chosen:** module tree under `cli/src/attacks/` + `cli/src/enums/` + `cli/src/dumps/` — NOT a new workspace crate.

Rationale — CLAUDE.md dual-use rule: attacker-only compositions stay inside adhammer CLI. The attack handlers are pure compositions of published protocol crates (`dcerpc`, `ntlmssp`, `smb2-client`, `ms-drsr`, …) — they have zero external-consumer appeal. A new workspace crate `adhammer-attacks` would just be a permission-slip publish with no downstream users.

Precedent — the existing cli-internal modules already follow this pattern: `cli/src/poison.rs`, `cli/src/dcshadow.rs`, `cli/src/adcs_relay.rs`, `cli/src/esc_registry.rs`, `cli/src/host_posture.rs`, `cli/src/winrm.rs` are all already extracted. arch-0 finishes that job for the remaining 65 handlers.

## Layout target

```
cli/src/
├── main.rs           — clap Command enum + dispatcher only (~1200 lines target, down from 5564)
├── attacks/
│   ├── mod.rs        — re-exports
│   ├── abuse.rs
│   ├── asktgt.rs
│   ├── badsuccessor.rs
│   ├── coerce.rs     (moves the CoercePipe enum + CoerceArgs + fn coerce)
│   ├── dcsync.rs
│   ├── esc1.rs
│   ├── esc4.rs
│   ├── golden.rs
│   ├── gmsa.rs
│   ├── icpr_esc1.rs
│   ├── laps.rs
│   ├── lsa.rs
│   ├── ptt.rs        (was pth — 1.3.10 rename)
│   ├── rbcd.rs
│   ├── relay.rs      (moves RelayTarget + RelayAction + RelayArgs + fn relay + relay_one)
│   ├── roast.rs
│   ├── samr.rs
│   ├── secretsdump.rs
│   ├── shadowcred.rs
│   ├── silver.rs
│   ├── spray.rs
│   ├── unconstrained.rs
│   ├── zerologon.rs
│   └── exec/         (subgroup — exec / wmiexec / atexec / winrm_exec share ExecArgs)
│       ├── mod.rs
│       ├── cmd.rs
│       ├── wmi.rs
│       ├── at.rs
│       └── winrm.rs
├── enums/
│   ├── mod.rs
│   ├── sessions.rs   (with wkssvc, hku — share SessionsArgs)
│   ├── net.rs
│   ├── posture.rs
│   ├── adcs.rs
│   ├── esc_registry.rs   (already extracted — thin wrapper)
│   ├── dns.rs
│   └── ...
├── dumps/
│   ├── mod.rs
│   ├── laps.rs
│   └── gmsa.rs
├── checks/
│   ├── mod.rs
│   └── adcs.rs
├── (existing) adcs_relay.rs, dcshadow.rs, guided.rs, host_posture.rs,
│              interactive.rs, poison.rs, session.rs, ui.rs, winrm.rs
```

## Migration rules

1. **Each handler moves with its Args struct.** `cli/src/attacks/coerce.rs` contains `CoercePipe` enum + `CoerceArgs` struct + `pub(crate) async fn coerce(a: CoerceArgs) -> Result<()>`.
2. **Args stay pub(crate)** so the top-level `Cli` enum in main.rs can `#[arg]` reference them via `attacks::coerce::CoerceArgs`.
3. **Handler fns become `pub(crate)`** so main.rs and interactive.rs can dispatch to them.
4. **Helpers stay in main.rs for now** — `resolve_secret`, `parse_nt_hash`, `parse_forge_key`, `smb_login`. Extract to `cli/src/helpers.rs` as a follow-on if it makes handlers cleaner.
5. **No behavior change per handler.** Byte-for-byte code move; if a handler needs a small tweak to compile after the move (e.g. an import path), do only that tweak in the same commit.
6. **Tests move with the code.** `mod resolve_secret_tests` stays in `main.rs` (it tests a main.rs helper). Any tests specific to a handler move to its file.

## Sequencing — 4 batches

Do the work in atomic commits, each independently `cargo build/test/clippy`-green.

**Batch 1 — small handlers (proof of pattern):** zerologon, badsuccessor, esc4, asktgt, spray, unconstrained. Each < 100 LOC handler. ~1 day. Establishes the module-tree, exposes any dispatch-import friction.

**Batch 2 — mid handlers:** poison (already extracted; leave), coerce, abuse, rbcd, shadowcred, silver, golden, samr, gmsa, laps, dns. Each 100-300 LOC. ~1 day.

**Batch 3 — large handlers + dispatch groups:** dcsync (+dcsync_all), relay (+relay_one +relay_esc8 +relay_esc11), exec/wmiexec/atexec/winrm (share ExecArgs — go together), secretsdump, esc1, icpr_esc1. ~1.5 days.

**Batch 4 — enum/dump/check groups + main.rs cleanup:** enum sessions/wkssvc/hku, netenum, posture_scan, adcsenum, dnsenum, esc_registry_scan, dump laps/gmsa, check adcs, scan, roast, ptt, unconstrained. Fold `mod enums/`, `mod dumps/`, `mod checks/`. Trim main.rs to Command enum + dispatch match + shared helpers + lib module. ~1.5 days.

**Total estimate: 5 days.**

## Non-goals

- No new features
- No `adhammer-attacks` published crate
- No shared-Args refactor (that's ux-0, separate follow-on)
- No `main.rs → lib.rs` split — cli stays a bin crate

## Verification per batch

```
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./target/debug/adhammer.exe --help                       # renders full command tree
./target/debug/adhammer.exe attack coerce --help         # each subcommand's --help still works
```

## Ship criteria

- All 71 async handlers moved out of main.rs
- main.rs < 2000 lines (goal)
- Every subcommand's `--help` renders unchanged
- Every subcommand parse-tests unchanged (typed enums still work)
- No new Cargo.toml deps
- No new workspace crates
- CI green: clippy `-D warnings`, 3-OS matrix, MSRV verify at 1.87
- Local-commit-atomic per batch (4 commits total)
- Push to main after each batch (small, reviewable diffs)

## Starter: Batch 1 pick

**`zerologon`** (line 3788 in main.rs, `ZerologonArgs` at line 242). Small handler, one clear entry point, safest first move.

If Batch 1 pattern works, replicate for the rest. If it hits friction (e.g. clap derive on cross-module Args struct), stop and iterate on the pattern before scaling.
