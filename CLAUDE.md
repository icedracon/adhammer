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
- Live site: https://icedracon.github.io/adhammer/ (source in `site/index.html`).
  Design language: blue-cyan `#2ea8ff` accent on near-black `#05070d` ground,
  Manrope (display) + IBM Plex Mono (mono). Wordmark: `AD//HAMMER`.

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

**★ Minimum-bump / SemVer honesty — HARD RULE, every crate (workspace + siblings).**
The version communicates **compatibility, not significance.** Bump only as far as the
change actually requires — never jump a minor/major to signal a milestone. **Verify the
real public-API delta before bumping.** Authoritative: `cargo semver-checks check-release`
(compares against the published version). Fast heuristic:
```
git show <range> --unified=0 | grep -E '^-.*pub (fn|struct|enum|trait|mod|const|type)'
```
Nothing printed (no pub item removed / renamed) ⇒ **likely** compatible ⇒ **stay on the
current version line** (patch bump within `^current`).
**Heuristic blind spot — reason about these, the grep won't catch them (they leave signature
TEXT unchanged but ARE breaking):** a redefined type alias (esp. an error alias like
`pub type Result<T> = …` switching `anyhow` → a typed enum), a changed trait bound, a
changed return/param type reached through an alias, a new/changed default trait method,
an enum gaining a variant without `#[non_exhaustive]`. Any of these ⇒ **breaking ⇒ minor**.
- **0.x crate** (`^0.y.z` = `>=0.y.z,<0.(y+1).0`): additive/bugfix → **patch** `0.2.5→0.2.6`
  (every `^0.2` consumer gets it free); breaking → **minor** `0.2.x→0.3.0`.
- **≥1.0 crate**: additive → minor, bugfix → patch, breaking → major.
- Why hard: an unneeded minor/major forces a **pin-bump cascade** across every dependent.
  Real case — dcerpc `0.3.0` was purely additive (21 pub added, 0 removed) and would have
  broken ~10 sibling `^0.2` pins + adhammer; re-versioned to `0.2.7`, zero pin changes.
  Reserve the next minor for a real break (e.g. dcerpc `drsuapi` removal → 0.4.0, already
  promised — never tighten a published deprecation target).

## Consumer safety — published crates have real downstream users (never crash / never break them)
These crates have external consumers (windows-sddl 2k+ dl, ntlmssp 2k+). Every change ships to them.

**Never break (API compatibility):**
- Minimum-bump rule (above) — breaking → minor/major so `^` shields old consumers.
- **`#[non_exhaustive]` on every public error enum** so future variants are a *patch*, not a break.
  New enums get it at creation; already-published enums get it **bundled with their next minor bump**.
- Deprecate, never yank the rug: `#[deprecated]` + removal-version promise, keep ≥1 minor cycle.
  Never tighten a published removal date.
- Additive-first: new capability = new method/module/crate (patch), not a changed signature.

**Never crash (panic-safety — a lib that panics on data crashes the CONSUMER's process):**
- A library **NEVER panics on input.** Malformed/hostile bytes → `Err`, never `unwrap()`/`expect()`/
  index-panic/`unreachable!`. Panics only on genuine programmer error.
- **Fuzz every wire parser** (cargo-fuzz; clone `dcerpc/fuzz`). A crate that parses attacker/server
  bytes is not publish-ready until it has a fuzz target and a clean run. Panic found → convert to `Err`.
- Bounded-alloc preflight on every wire-derived length; checked/saturating arithmetic on length math.

**Never lock out (MSRV):** keep `rust-version` accurate and as low as the dep closure allows; pin
heavy deps down rather than raise the floor.

**Per-crate publish gate (grandiose update):**
`fmt → clippy -D → test → FUZZ (0 panics) → cargo semver-checks → bounded-alloc audit → --dry-run → publish → verify index`

## What NOT to do
- **Rule for new crates:** extract only when the primitive has genuine **dual-use** appeal
  (used by defensive / admin / DFIR tools too, not just offensive). Attacker-only compositions
  stay inside adhammer CLI. As of 2026-08-21 the count is 43 external protocol crates + 12
  workspace + 4 legacy stubs (superseded) + 2 unrelated (`whenparse`, `hashglass`) = 61 total.
- Don't add `adhammer-ntlm`, `adhammer-dcerpc`, `adhammer-smb`, `adhammer-sddl` —
  these are legacy 0.0.1 stubs on crates.io, superseded by standalone protocol crates.
- Don't create docs/README files unless explicitly asked.
- Don't add features, refactor, or abstract beyond what the task requires.
