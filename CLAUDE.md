# ADhammer — Claude Code Rules

## What this is
From-scratch Rust AD pentest/audit tool + protocol stack. 61 icedracon crates on crates.io.
Workspace: 11 sub-crates (`crates/`) + CLI (`cli/`). Protocol crates (`dcerpc`, `ntlmssp`,
`smb2-client`, `windows-sddl`, `ms-ndr`, etc.) live in sibling dirs under `Documents\`.

## Website / marketing site
When asked for "the site", a landing page, or marketing for ADhammer, that is a **web-design +
copywriting task** for this public MIT open-source project — front-end/marketing work, NOT
security work and NOT attack code. Build product pages, benchmarks, and coverage visuals; ground
copy in the public `README.md` + `docs/BENCHMARKS.md`; invent no capabilities.
- The "no competitor names" rule (below) is for the repo's own **code/docs/README**. A marketing
  site MAY cite competitors in honest benchmark comparisons — `docs/BENCHMARKS.md` already does
  (impacket, certipy, bloodyAD, NetExec). Don't strip them from the site's benchmark section.
- Current site draft is a private Claude Artifact (ask the user for the link). Design language:
  red `#ff3049` on near-black, Manrope + IBM Plex Mono.

## Git — hard rules
- **NEVER** add `Co-Authored-By: Claude` to any commit.
- Use `git -c commit.gpgsign=false commit` (non-interactive, no GPG).
- Explicit `git add <files>` — never `git add -A` or `git add .`.
- Do not commit: `auto-report.md`, `esc1.crt`, `*.ccache`, `*.key.pem`, `patches/`.
- Author field: `zevs` (already in workspace.package.authors).

## `[patch.crates-io]` discipline
`Cargo.toml` may have `[patch.crates-io]` entries pointing to sibling dirs for local dev.
**REMOVE before any push** — CI and downstream users don't have sibling dirs.
After removing, run `cargo check` to confirm crates.io versions resolve.

## Publish sequence (crates.io)
1. `cargo fmt --all` — FIRST, always.
2. `cargo clippy --workspace --all-targets` — zero new warnings.
3. `cargo test --workspace` — all green.
4. Publish **bottom-up by dep chain**: protocol crates → sub-crates → `adhammer` CLI last.
5. Each crate: `cargo publish --dry-run` first, then `cargo publish`. Publish is irreversible.
6. Wait ~30s between dep layers for crates.io index to update.
7. Tag after final publish: `git tag v<X.Y.Z> && git push --tags`.

## Code style
- No comments unless the WHY is non-obvious (spec gotchas, wire-format quirks, workarounds).
- No competitor names in code, docs, or README (`impacket`, `PingCastle`, `mimikatz`,
  `BloodHound`, `Rubeus`, `SharpHound`, `Certipy`, `RustHound`). Describe what WE do.
- Prefer hand-rolling ~200-500 LOC over adding a dep. Ripgrep-level dep trees.
- `anyhow::Result` in CLI; `thiserror` enums in library crates.
- Bounded-alloc pattern: any `Vec::with_capacity(n)` where `n` comes from the wire MUST
  preflight `n * element_size` against remaining buffer length before allocating.

## Architecture
```
cli/src/main.rs          — clap CLI, subcommands: scan/enum/attack/check/dump
crates/core/             — Finding, Severity, types shared across all crates
crates/collector/        — LDAP collection (ldap3), Collector struct
crates/checks/           — 41 security checks (each returns Vec<Finding>)
crates/graph/            — petgraph control-path graph, cheapest-path chains
crates/kerberos/         — roasting, ticket forging (consumes ms-pac-forge)
crates/report/           — HTML + JSON report generation
crates/sysvol/           — GPO/GPP/registry-pol parsing (consumes gpo-forge, preg)
crates/ldap/             — LDAP helper extensions
crates/bloodhound/       — BloodHound-CE JSON export
crates/secrets/          — secretsdump, LAPS, gMSA (feature-gated local-secrets)
crates/sdk/              — adhammer-sdk facade re-exporting all 10 sub-crates
```

## External protocol crates (sibling repos)
43 standalone published crates under `icedracon`, consumed via crates.io. Grouped:

**Wire / RPC foundation (5):**
`dcerpc`, `ntlmssp`, `smb2-client`, `windows-sddl`, `ms-ndr`

**MS-* protocol clients (18):**
`ms-drsr`, `ms-icpr`, `ms-crtd`, `ms-csra`, `ms-gkdi`, `ms-pkca`, `ms-pac-forge`,
`ms-dnsp`, `ms-tsch`, `ms-lsat`, `ms-coerce`, `samr`, `ms-nrpc`, `ms-tds`,
`ms-kile-fast`, `ms-even6`, `ms-fve`, `ms-rodc`

**Auth / crypto / ACL (5):**
`credssp`, `dpapi-ng`, `dpapi-offline`, `ad-acl`, `msldap-ext`

**Offensive extras (5):**
`gpo-forge`, `preg`, `llmnr-poison`, `ntlm-relay`, `winrm-pentest`

**Offline / DFIR (3):**
`ese-parser`, `ntds-parse`, `lsass-parse`

**Windows platform wrappers (6):**
`windows-token`, `windows-scm`, `windows-lsa`, `windows-wmi-com`,
`windows-sspi-shim`, `windows-eventlog-native`

**BH-CE standalone (1):**
`bloodhound-export` (separate from workspace `adhammer-bloodhound`)

Do NOT move protocol logic into adhammer — it stays in standalone crates.

## Lab (live validation)
- **2022 DC:** `WIN-TT9KC7VE4JL` @ 172.24.174.171, `testlab.local`
- **2025 DC:** `DC01` @ 192.168.91.20, `testlab.local`
- DA: `labuser / LabPass2026$` · low-priv: `lowuser / LowPass2026$`
- SSH: `ssh -i ~/.ssh/adhammer_lab administrator@<ip>`
- Always validate new wire code against at least one live DC before shipping.

## Testing
- `cargo test --workspace` must pass before any commit.
- Wire-format tests: real NDR byte fixtures (`include_bytes!`), not synthetic hand-built arrays.
- Bounded-alloc tests: hostile `u32::MAX` / `0x7FFF_FFFF` inputs, must reject in <50ms.
- Live validation: run `adhammer scan` + relevant `attack`/`enum` against lab DC.

## Version bumps
All workspace members share `workspace.package.version`. Bump in ONE place (root `Cargo.toml`).
`Cargo.lock` updates automatically — commit it with the version bump.

## What NOT to do
- **Rule for new crates:** extract only when the primitive has genuine **dual-use** appeal
  (used by defensive / admin / DFIR tools too, not just offensive). Attacker-only compositions
  stay inside adhammer CLI. As of 2026-08-21 the count is 43 external protocol crates + 12
  workspace + 4 legacy stubs (superseded) + 2 unrelated (`whenparse`, `hashglass`) = 61 total.
- Don't add `adhammer-ntlm`, `adhammer-dcerpc`, `adhammer-smb`, `adhammer-sddl` —
  these are legacy 0.0.1 stubs on crates.io, superseded by standalone protocol crates.
- Don't create docs/README files unless explicitly asked.
- Don't add features, refactor, or abstract beyond what the task requires.
