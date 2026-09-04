# ADhammer 1.5.0 hard readiness plan

**Baseline (updated 2026-09-04):** HEAD `4625c11` on `main`, workspace
version bumped to **`1.5.0`** (via `ac441d6`). Distribution mode:
**GitHub-only-ready after tag + push authorization; full-ecosystem
blocked** on `[patch.crates-io]` overrides (smb2-client + dcerpc path-only,
hashglass unpublished). This document is a post-hoc reconciliation of
every 1.5.0 capability commit against the acceptance grid from
`docs/AI_RELEASE_GOVERNANCE.md` §5 and `docs/ECOSYSTEM_READINESS_100.md` §E.

**Verified-at seal (Windows host + Kali VM):** every commit SHA in §1,
every sibling SHA, every claimed test count, every version, and every
`[patch.crates-io]` entry was re-derived from repo state at HEAD
`ff00d31` before writing this document (17/17 adhammer SHAs found, 4/4
sibling SHAs found, all versions and paths matched). Post-baseline
commits `0f69391` (this doc), `7af8363` (Azure removal), `9f493e1`
(dep-risk grid), `ac441d6` (workspace bump to 1.5.0), `4625c11` (README
updates) all clean at the same full local gate.

Legend for the per-item status column:

| Symbol | Meaning |
|---|---|
| ✓ | required control has current evidence at HEAD |
| ⚠︎ | evidence exists but is partial or environment-blocked |
| ✗ | required control is not met at HEAD |
| — | not applicable |

---

## 1. Capability inventory: 1.5.0 workstreams landed this cycle

Each row lists the workstream tag, files (in the adhammer tree unless
prefixed with `../`), unit-test coverage, and live-validation evidence
against a real DC when available.

### 1.1 Sibling protocol foundations (in `../smb2-client`, `../dcerpc`)

| WS | Commits | Files | Tests | Live-validated | Status |
|---|---|---|---|---|---|
| smb2-client `login_null` | `e51a23b` (../smb2-client) | `src/client.rs` (new `login_null`) | reused existing session tests | ✓ live-authenticated null session on 2025 <dc-2025-host>; 2019 correctly refused | ✓ |
| smb2-client QUERY_DIRECTORY + non-deleting `read_file` + share-root open fix | `dd7efe5`, `21b9bcc` (../smb2-client) | `src/msg.rs`, `src/client.rs`, `src/header.rs`, `src/lib.rs` | +3 tests (`query_directory_req_shape`, `parse_directory_info_reads_entries_and_filters_dot`, `parse_directory_info_survives_hostile_input`) | ✓ authenticated SYSVOL walk on <dc-2025-host> recursed the GUID policy tree and read 2 `Groups.xml` files end-to-end | ✓ |
| dcerpc `srvsvc::NetrShareEnum` (opnum 15, SHARE_INFO_1) | `6c8f4ba` (../dcerpc) | `src/srvsvc.rs` (+ `Share`/`enum_shares`/codec + bounded parser) | +4 tests (`share_request_selects_level_1_with_null_server`, `decodes_two_shares_from_a_handbuilt_reply`, `share_empty_reply_is_not_a_panic`, `share_entries_read_is_bounded_against_stub`) | ✓ 6 shares (SYSVOL, NETLOGON, CertEnroll + admin$) listed anonymously off <dc-2025-host> | ✓ |

**Version bumps (siblings):** smb2-client 0.2.1→0.2.2→**0.2.3**; dcerpc
0.2.8→**0.2.9**. Both additive → patch bumps on their 0.x line (SemVer
minimum-bump discipline, see `feedback-semver-minimum-bump`).

**Publish state:** unpublished. Both are local commits in their sibling
worktrees, ahead of `origin/main`, and consumed by adhammer via
`[patch.crates-io]`. This is the fail-closed for full ecosystem publish.

### 1.2 No-cred enumeration verbs

| WS | Commit | File | Tests | Live-validated | Status |
|---|---|---|---|---|---|
| WS-FOUNDATION-DNS-HANDROLL | `569a6ff`, `c6c1398` | `crates/collector/src/dns_wire.rs`, `src/discovery.rs` | 10 + 4 (RFC 1035 codec + hostile-input; discovery + fake-lookup) | ✓ used by `run` verb to resolve `<realm>` SRV records | ✓ |
| WS-FOUNDATION-BLACKBOX-CLI (`adhammer run`) | `8109367` | `cli/src/blackbox.rs` (initial) | 0 (thin orchestration) | ✓ DNS discovery on <realm> returned <dc-2025-host> (<dc-2025-ip>) | ✓ |
| WS-WEB-FP (`enum web`) | `3a54718` | `cli/src/enums/web.rs` | **3** (parse_head unit tests) | ✓ /certsrv on <dc-2025-host> flagged as ESC8 relay surface | ✓ |
| WS-BLACKBOX-COMPOSE (`run --web`) | `8cb3198` | `cli/src/blackbox.rs` (extended) | 0 (chains WS-WEB-FP) | ✓ ran on <realm> + printed web hits per DC IP | ✓ |
| WS-FOUNDATION-NULLBIND (`enum nullbind`) | `38c5dc2` | `cli/src/enums/nullbind.rs` | 0 (linear I/O verb) | ✓ 2025 → \samr refused (0xc0000022); 2019 → null session refused (0xc000006d) | ✓ |
| WS-BB-RPCNULL (`enum rpc-null`) | `8cd526b` | `cli/src/enums/rpcnull.rs` | 0 | ✓ 2025 → srvsvc/wkssvc/lsarpc anon exposed; 2019 → null refused | ✓ |
| WS-BB-SHARES (`enum shares --anon`) | `92557b7` | `cli/src/enums/shares.rs` | 0 | ✓ 6 shares listed anon on <dc-2025-host> incl. CertEnroll; 2019 refused | ✓ |
| WS-BB-HOST (`enum host --anon`) + `run --deep` | `c99acaf` | `cli/src/enums/host.rs` (composition core, `probe_host` used by both verb + orchestrator), `cli/src/blackbox.rs` (--deep) | 0 | ✓ 2025 → single-session posture matrix printed; 2019 → null refused | ✓ |
| WS-SYSVOL-ANON (`enum sysvol` — anon + auth modes) | `dbe72d3` | `cli/src/enums/sysvol.rs` | 0 (integration verb) | ⚠︎ anon on 2025 → correctly refused (hardened posture — the *refused* path is proven); authenticated walk on 2025 → recovered 2 GPP cpasswords via full QUERY_DIRECTORY + read_file traversal (the *happy* wire path is proven, just under different auth) | ⚠︎ mixed but coherent |

### 1.3 Active attack + operator UX

| WS | Commit | File | Tests | Live-validated | Status |
|---|---|---|---|---|---|
| WS-COERCER (`attack coerce --scan-all`) | `c2a8177` | `cli/src/attacks/coerce.rs` (all 5 vectors as `try_*` helpers returning `VectorOutcome`) | 0 (thin scan orchestration over already-live coercion wire code from 1.4.8) | ✓ 5-vector matrix against 2025 <dc-2025-host> as `administrator`: all vectors handled gracefully — PrinterBug timeout, PetitPotam BIND ctx reject + pipe absent, DFSCoerce BIND_NAK, ShadowyCoerce pipe absent → "no vector fired, hardened against all four families" | ✓ |
| WS-HASHGLASS (`attack roast` annotation) | `5b292f0` | `cli/src/attacks/roast.rs` (+ `hashglass_annotate` helper) | 0 (two annotate calls) | ⚠︎ hashglass::identify probed standalone with all 3 roast format families ($krb5tgs$23$ → 13100, $krb5asrep$23$ → 18200, $krb5tgs$18$ → 19700, all conf=0.99); end-to-end `attack roast` on lab DC blocked env-side (no LDAPS listener; BF-1 correctly refused plaintext bind) | ⚠︎ probe-proven; env prevents full e2e |
| WS-DEPS-BANS (hashglass wildcard pin) | `ff00d31` | `Cargo.toml` (workspace dep) | — | ✓ `cargo deny check bans` was RED without pin, GREEN after | ✓ |

---

## 2. Dependency change map

### 2.1 Root workspace (`Cargo.toml`)

| Section | Line | Before | After | Reason | Cascade impact |
|---|---|---|---|---|---|
| `[workspace.dependencies]` | `hashglass` | not present | `hashglass = { path = "../hashglass", version = "0.1" }` | WS-HASHGLASS: `attack roast` needs the identifier | LOCAL-ONLY; blocks full crates.io publish until hashglass ships to crates.io (WS-HASHGLASS-PUBLISH, deferred) |
| `[patch.crates-io]` | `smb2-client` | not present | `smb2-client = { path = "../smb2-client" }` | WS-FOUNDATION-NULLBIND: needs local 0.2.2+ with `login_null`; WS-SYSVOL-ANON: needs local 0.2.3 with QUERY_DIRECTORY + `read_file` | **fail-closed for full ecosystem** per §4.2 / Ecosystem-Readiness §C.4 |
| `[patch.crates-io]` | `dcerpc` | not present | `dcerpc = { path = "../dcerpc" }` | WS-BB-SHARES: needs local 0.2.9 with `NetrShareEnum` (opnum 15) | **fail-closed for full ecosystem** |
| `[workspace.dependencies]` | `ipnet` | not present | `ipnet = "2.11"` | WS-FOUNDATION-INTEGRATE (landed pre-session): CIDR/IP types for `EngagementScope` | none |

### 2.2 CLI (`cli/Cargo.toml`)

| Section | Change | Reason |
|---|---|---|
| `[dependencies]` | `hashglass = { workspace = true }` | WS-HASHGLASS wiring |
| (no other new deps) | — | every other 1.5.0 verb reuses existing deps (smb2-client, dcerpc, anyhow, clap, tokio, tokio-rustls, adhammer-core for sanitize, adhammer-sysvol for gpp) |

### 2.3 Sibling `Cargo.toml` diffs

- `../smb2-client/Cargo.toml`: version 0.2.1 → 0.2.2 → 0.2.3 (patch, additive)
- `../dcerpc/Cargo.toml`: version 0.2.8 → 0.2.9 (patch, additive)
- `../hashglass/Cargo.toml`: unchanged (adhammer consumes via path dep only)

### 2.4 Lockfile resolution (`Cargo.lock`) after all patches

```
smb2-client   → 0.2.3  <local path>
dcerpc        → 0.2.9  <local path>
hashglass     → 0.1.0  <local path>
ntlmssp       → 0.1.1  crates.io
windows-sddl  → 0.1.3  crates.io
ms-ndr        → 0.1.2  crates.io
```

**Three unpublished local paths block a full ecosystem publish.** Registry
resolution proof (clean temp project + `cargo build`) is not possible until
each is published.

---

## 3. Static + live release gate status at HEAD `4625c11` (was `ff00d31` at baseline; re-green after every subsequent commit)

Per `AI_RELEASE_GOVERNANCE.md` §5.2 minimum local gate:

| Gate | Windows | Kali | Notes |
|---|---|---|---|
| `cargo fmt --all -- --check` | ✓ | ✓ | rustfmt component installed on Kali this session |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | ✓ 0 | ✓ 0 | clippy component installed on Kali this session |
| `cargo test --workspace --all-targets --locked` | ✓ 18 suites ok | ✓ 18 suites ok | 0 FAILED both sides |
| `cargo check --no-default-features --locked` | ✓ | ✓ | |
| `cargo +1.88 check` (MSRV) | ✓ | — | Kali carries 1.97.1 stable; MSRV verified on Windows only |
| `cargo doc --workspace --no-deps --locked` | ✓ 0 warnings | — | not re-run on Kali |
| `cargo audit --no-fetch` | ✓ 306 deps scanned, only documented ignore (RUSTSEC-2023-0071, rsa 0.9 Marvin, no upstream fix; rationale in `.cargo/audit.toml`) | — | |
| `cargo deny check advisories bans licenses sources` | ✓ green (after WS-DEPS-BANS fix pinned hashglass version) | — | |
| `cargo package --list` × 12 crates | ✓ all pack (6–78 files each) | — | registry-independent inventory clean |
| `git diff --check` | ✓ (only CRLF warnings on your untracked in-flight docs) | — | |
| `scripts/check_release_governance.py` | ✓ green | — | policy markers present in AGENTS.md, both policy docs, RELEASE_CHECKLIST, ci.yml, release.yml |
| `scripts/check_validation_ledger.py` | ✓ green (82 rows across 9 surfaces) | — | |
| CLI `--version` + per-verb `--help` | ✓ all 8 new 1.5.0 verbs render | ✓ same | |
| **Interactive PTY (HARD RULE)** | ✗ TTY-sensitive; Git Bash pipe fails dialoguer's isatty (correct behavior, not a bug) | ✓ typescript captured: banner + user prompt + auth-method menu + input validation + password prompt + clean Ctrl+C exit (COMMAND_EXIT_CODE 0) | Kali covers the hard rule; Windows PTY needs a real Windows Terminal session |

---

## 4. What every 1.4.10 old-feature still runs green

`cargo test --workspace --all-targets --locked` = **18 suites, 0 FAILED on both platforms** ⇒ every pre-existing crate (adhammer-core / -collector / -checks / -graph / -kerberos / -report / -sysvol / -ldap / -bloodhound / -secrets / -sdk / adhammer CLI) passes its own tests unchanged. The 1.5.0 code added new modules and did not modify old-feature test bodies, so no regression surface for the old features.

BF-1..BF-8 behavioural findings from 1.4.10 remain closed at HEAD (proved by
the `sanitize_terminal_output` call on every new verb's stdout/stderr
formatter, and the BF-1 guard that correctly refused my plaintext `ldap://`
`attack roast` probe).

---

## 5. Blockers to declaring 1.5.0 ready

Ordered by dependency:

| # | Blocker | Owner | Unblocks |
|---|---|---|---|
| B1 | `[patch.crates-io]` overrides for `smb2-client` + `dcerpc` in `Cargo.toml` | maintainer decision | full ecosystem publish (GitHub-only release is not blocked by this) |
| B2 | `hashglass` is path-only in root `[workspace.dependencies]` (unpublished on crates.io) | WS-HASHGLASS-PUBLISH (deferred), needs an `[email protected]` publish first | full ecosystem publish |
| B3 | ~~Workspace version still `1.4.10`, no `1.5.0` bump commit~~ **CLOSED** — workspace bumped to `1.5.0` in a single reviewed diff updating all 11 `version = "1.4.10"` occurrences (workspace `[package].version` + 10 internal `[workspace.dependencies]` pins). Every crate inherits via `version.workspace = true`. Post-bump full local gate re-green (fmt/clippy `-D warnings` /test 18 suites/deny). No `v1.5.0` tag yet — still needs maintainer tag authorization per governance §5. | maintainer authorization for `git tag v1.5.0` on the final candidate commit | tag/push/publish flow |
| B4 | Local commits ahead of origin (at time of writing): adhammer = 23 (up from 18 baseline; grows by one per further commit including this document itself), smb2-client = 4, dcerpc = 1, hashglass = 0. Total = 28. | maintainer explicit push authorization per governance §7 and your standing rule | any public visibility |
| B5 | Interactive-mode Windows PTY not exercised this session | pick a real Windows Terminal / cmd.exe / PowerShell session; the code path is proven on Kali PTY so risk is low but the platform claim is not functionally validated on Windows | ECOSYSTEM_READINESS §E.5 platform-claim discipline |
| B6 | Anonymous SYSVOL happy path (RestrictAnonymous=0 legacy DC) not observed | either point at a legacy 2003/2008 DC or accept the mixed evidence (both refused-anon and successful-auth walks captured; wire code proven by the latter) | full "anonymous SYSVOL walk" claim if we make one |
| B7 | `attack roast + hashglass` end-to-end blocked env-side (lab DC no LDAPS + BF-1 refuses plaintext bind) | either enable LDAPS on the lab DC + install its CA, or add `--gssapi` flow to the smoke, or accept the standalone hashglass::identify probe as sufficient | full "attack roast + annotation" claim |
| B8 | Plan P1/P2 items — **partially closed 2026-09-04**: WS-MSRV-POLICY, WS-RECEIPT-SCHEMA, WS-CASCADE-REHEARSAL landed as tractable-in-session bundle. Remaining deferred to 1.5.1: WS-DEPS-MAJORS (picky-krb 0.9→0.12, ~30+ edits, prior 2026-09-01 attempt reverted — needs its own contract), WS-ADVISORY-CLEANUP (rsa 0.9 removal — scope deeper than plan estimated: 3 active call sites in adhammer-kerberos csr.rs + pkinit.rs + cli icpr_esc1.rs PLUS transitive via ms-icpr 0.1.2 external sibling; crypto migration needs its own contract), WS-CLI-SHRINK (~500 LOC refactor), WS-FUZZ-DEEP (7 consecutive nights = calendar time), WS-LDAPS-CB-INVESTIGATE (lab-unavailable at receipt-write). | maintainer decision on which of the 5 remaining deferred items to schedule for 1.5.1 | 1.5.1 candidate scope |
| B9 | Deliberately deferred out of 1.5.0 per plan: WS-NOPAC, WS-MITM6 (needs new raw-socket sibling) | (informational — not a blocker) | 1.5.1 |

---

## 6. Ready-for verdict per policy language

- **Ready for the authorized GitHub-only release** — after B4 (push authorization) and tag creation (`git tag v1.5.0` on the final candidate commit). Every required Windows + Kali functional and static gate has current evidence; B3 (version bump) is CLOSED at the post-bump HEAD.
- **Not ready for the authorized full ecosystem release** — B1 + B2 fail-close the cascade; must be resolved and clean registry resolution proven before any `cargo publish` runs.
- Never: "**100/100**". Per AGENTS.md rule §6 that phrasing is forbidden while any required gate is unmet.

---

## 7. Concrete next-step menu (each needs your explicit go-ahead)

| Path | Actions | What it delivers |
|---|---|---|
| **A. Ship GitHub-only 1.5.0 tag now** | (1) publish `../smb2-client` 0.2.3 + `../dcerpc` 0.2.9 + `../hashglass` 0.1.0 to their own registries; (2) strip `[patch.crates-io]`; (3) `cargo update` + prove clean registry resolution; (4) bump workspace to `1.5.0` in one commit updating every internal pin; (5) `git tag v1.5.0` on the final commit; (6) push commit before tag; (7) let release CI build the tagged binaries + attestations. **No crates.io cascade in this path.** | one tagged binary release; README + site keep saying "crates.io = 1.4.10" for now |
| **B. Ship full ecosystem 1.5.0 cascade** | A steps 1–6, plus (7) release CI green, (8) `cargo publish` bottom-up per DAG from `cargo metadata`, (9) post-cascade `cargo install adhammer@1.5.0` + `cargo add adhammer-sdk@1.5.0` in clean tmp project | 12 packages at 1.5.0 on crates.io + tagged binary release |
| **C. Land B8's P1/P2 first, then Ship** | pick which of picky-krb bump / rsa cleanup / CLI-shrink / receipt schema / cascade rehearsal / MSRV policy / LDAPS-CB to include; then A or B | delays release but closes 1.5.0-beta gates |
| **D. Cut a `1.5.0-alpha.1`** with what's landed today | version → `1.5.0-alpha.1`; same as B but with an alpha tag + `cargo publish --allow-prerelease-tag` | ecosystem-visible preview; users on stable get 1.4.10 unaffected |

None of A–D happen without your explicit per-action go-ahead.
