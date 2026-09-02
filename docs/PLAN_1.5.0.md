# ADhammer 1.5.0 — canonical plan

Written 2026-09-02. Supersedes:
- `docs/PLAN_1.5.0_REVAMP.md` (untracked; kept in-tree for now with
  a superseded header)
- `docs/PLAN_1.5.0_100_100_ANALYSIS.md` (committed `383c47c`;
  kept in-tree with a superseded header)
- The earlier tracked `docs/PLAN_1.5.0.md` this file now replaces

Nothing below is claimed unless it survives verification. `cargo test`,
Clippy, MSRV 1.88 and offline `cargo audit` all pass at
`main` today; every other statement is either backed by grep, by a
build result, or is flagged as **HYPOTHESIS — packet-trace or live-DC
evidence owed before it becomes a decision**.

## Ship policy (locked)

**1.5.0 stays LOCAL until `WS-CASCADE-REHEARSAL` closes green.** Same
rule as 1.4.9. When the plan says "publish sibling crate X 0.y.z", the
git tree gains the version bump; `cargo publish` waits for rehearsal.
Only exception: a sibling-crate bump required to close a live RustSec
advisory — that one publish is justified same-cycle. There is no
"restore normal cadence early" clause.

## Sibling-crate breaking-changes policy (locked)

Tier-1 siblings (`windows-sddl`, `ad-acl`, `ccache-io`, `win32-min`) —
no breaking changes during 1.5.0. Publish tier-1 first so downstream
can pin before tier-2 churn.

Tier-2 siblings (touched during `WS-DEPS-MAJORS`, `WS-ADVISORY-CLEANUP`
or `WS-FOUNDATION-INTEGRATE`) — breaking changes allowed with an ADR
under `docs/adr/` recording the trigger + migration.

## Verified code-state audit (2026-09-02)

### Passes today
- `cargo test --workspace` — green.
- `cargo clippy --workspace --all-targets -- -D warnings` — green.
- `cargo build --workspace` at MSRV 1.88 — green.
- Offline `cargo audit` — passes with the standing `RUSTSEC-2023-0071`
  ignore for `rsa 0.9.10` (Marvin sidechannel; closes in
  `WS-ADVISORY-CLEANUP`).

### Fails today (blocks release)
- **CI-FAIL-1**: `cargo check --workspace --all-features` fails on
  `ldap3` with 15 errors: `--features tls-native,tls-rustls` are
  mutually exclusive and both wire in under `--all-features`. Fix in
  `WS-FEATURE-MATRIX`.
- **CI-FAIL-2**: `cargo fmt --all --check` fails on
  `cli/tests/live_safe.rs:120` (untracked test file — `run(&["attack",
  "zerologon", …])` needs multi-line reformat). Fix in the same commit
  that lands the file into tracking.

### Untracked-but-on-disk (foundation drift)
- `crates/core/src/scope.rs` — draft `EngagementScope`, `ScopeTarget`,
  hostname normalization. Not `mod scope;`-declared in
  `crates/core/src/lib.rs`; not compiled.
- `crates/collector/src/discovery.rs` — draft DNS SRV discovery using
  `hickory-resolver`. Not `mod discovery;`-declared in
  `crates/collector/src/lib.rs`; not compiled. `hickory-resolver` +
  `ipnet` are NOT in any `Cargo.toml` yet.
- `crates/sdk/src/blackbox.rs` — 176-LOC control-plane scaffold
  (`RunPolicy`, `ConsentPolicy`, `CheckSelection`). Not
  `mod blackbox;`-declared in `crates/sdk/src/lib.rs`; not compiled.
  SDK today is a pub-use façade only.
- `cli/tests/live_impact.rs`, `cli/tests/live_safe.rs`,
  `cli/tests/common/` — untracked live-DC integration test files
  (source of CI-FAIL-2).

The previous `docs/PLAN_1.5.0_REVAMP.md` claimed the foundation was
"already implemented locally"; the disk files exist but nothing is
integrated. `WS-FOUNDATION-INTEGRATE` closes this drift; it is P0.

### Behavioural findings (from the same audit — each becomes a same-cycle same-plan workstream)
- **BF-1** LDAP collector `crates/collector/src/lib.rs:327` calls
  `ldap.simple_bind(&bind_dn, cfg.password.expose_secret())` without
  requiring a verified integrity channel (SASL sealing / verified
  LDAPS). AH-003 refused a specific *write* path in 1.4.9; the *read*
  simple-bind path is still open. Fold into `WS-LDAP-INTEGRITY`.
- **BF-2** `crates/sysvol/src/gpp.rs:20` — `decrypt_cpassword` returns
  `Result<String>`; caller responsibility to wrap in `SecretString`.
  If a caller stashes into a `Finding`, plaintext GPP password reaches
  `Debug`, JSON report and MD report unredacted. Fold into
  `WS-SECRET-BOUNDARY`.
- **BF-3** Draft `EngagementScope::contains_ip` and
  `contains_hostname` are separate paths; a target excluded by name
  can be re-included by IP (and vice versa). Excludes must win across
  all identity forms. Fix in `WS-FOUNDATION-INTEGRATE` before the code
  ever lands into tracking.
- **BF-4** Draft `RunPolicy` fields `max_hosts`, `max_duration_secs`
  and `ConsentPolicy.allow_impact` / `allow_spoof` are not enforced
  anywhere the code compiles today. Fix in `WS-FOUNDATION-INTEGRATE`.
- **BF-5** No capability gate on `CheckClass::PostCred` — a PostCred
  check can currently be selected without a landed credential
  capability. Fix in `WS-FOUNDATION-INTEGRATE` when the runner path is
  brought online.
- **BF-6** No centralized secure-write policy for artifact files
  containing secrets (ccache, hashcat-input, GPP dumps). Filesystem
  perms + shred-on-drop are ad-hoc. Fold into `WS-SECRET-BOUNDARY`.
- **BF-7** LDAP + SYSVOL collectors lack global response-size / walk-
  depth / per-call deadline budgets. WinRM has these under AH-004/005;
  LDAP + SYSVOL do not. Fold into `WS-LDAP-INTEGRITY` (for LDAP) and
  `WS-SYSVOL-BUDGETS` (for SYSVOL).
- **BF-8** Network-controlled text (server banners, LDAP attribute
  values, GPO comment fields) reaches stdout without control-character
  sanitization; a hostile target can inject ANSI escapes or embed
  U+0007 in report output. Fold into `WS-OUTPUT-SANITIZE`.

## Score model — 4 axes, computed from release gates only

Score is `sum(gate_pass ? weight : 0)`. **A workstream that ships new
verbs but doesn't turn a gate green is worth 0 score points.**

| Axis | Weight | Gates → weight |
|---|---|---|
| **Correctness + supply chain** | 25 | `cargo audit` 0-ignores (+8) · `cargo deny check` 0-skips (+4) · fuzz 7-nights-clean (+5) · reproducible-build attestation green (+4) · SBOM + sigstore evidence bundle green (+4) |
| **Protocol coverage — no-cred** | 25 | Foundation integrated (+5) · DNS SRV + RootDSE + SMB null probe scope-driven (+5) · Anonymous SMB SYSVOL cross-platform walk (+3) · HTTP fingerprint on AD web surface (+3) · Coerce scan-all mode (+3) · SNMP + web fingerprint at range (+3) · Black-box orchestrator ties them into one run (+3) |
| **Protocol coverage — post-cred** | 25 | Every 1.4.9 authed verb still passing (+8) · LDAPS-CB *if evidence justifies* (+5) · picky-krb 0.9→0.12 + BUG-19 retired (+5) · NTDS.dit offline (+4) · noPac CVE-2021-42278 (+3) |
| **Ecosystem + operator UX** | 25 | Foundation SDK is real orchestration API not façade (+5) · CLI-shrink into SDK done (+4) · Per-crate MSRV published (+3) · Receipt schema + validator in CI (+4) · CASCADE-REHEARSAL green (+5) · Cross-version live-DC receipts approved (+4) |
| **Total self-reachable** | **100** | **91 without external audit / 6-month track record / red-team attestation** |

**Verified baseline today:** ~64/100. Every point above 64 requires a
gate to close, not a verb to ship.

## True gap-list (grep-verified, mapped to code)

Anything that is not in this list is either already in the tree or is
a 1.5.1+ item. Nothing is claimed as "gap" unless every file below has
been grep'd and confirmed missing.

| ID | Gap | Verified missing where | LOC est | ROI | Path |
|---|---|---|---|---|---|
| G-1 | Foundation files tracked + integrated + tests | `git ls-files` on scope.rs/discovery.rs/blackbox.rs = untracked; `grep '^mod scope\\|blackbox\\|discovery'` in lib.rs = 0 hits | ~400 (+ 200 test) | ★★★★★ | `WS-FOUNDATION-INTEGRATE` |
| G-2 | Feature-matrix hygiene (tls-native ⊕ tls-rustls) | `cargo check --all-features` fails ldap3 with 15 errors | ~30 | ★★★★ | `WS-FEATURE-MATRIX` |
| G-3 | LDAP simple-bind integrity requirement | collector `ldap.simple_bind` unconditional at line 327 | ~150 | ★★★★ | `WS-LDAP-INTEGRITY` |
| G-4 | GPP secret boundary + Debug redaction | `decrypt_cpassword -> Result<String>` — plain caller wrap only | ~120 | ★★★★ | `WS-SECRET-BOUNDARY` |
| G-5 | LDAP + SYSVOL resource budgets | no `MAX_RESPONSE_BYTES`, no walk-depth cap in either collector | ~200 | ★★★ | `WS-LDAP-INTEGRITY` + `WS-SYSVOL-BUDGETS` |
| G-6 | Output control-char sanitization | no `sanitize_terminal_output` helper called on network-derived strings | ~80 | ★★★ | `WS-OUTPUT-SANITIZE` |
| G-7 | picky-krb 0.9 → 0.12 (BUG-19 killer) | attempt 2026-09-01 reverted; 30+ mechanical edits owed | ~300 edits | ★★★★★ | `WS-DEPS-MAJORS` |
| G-8 | `rsa 0.9` advisory removal (RUSTSEC-2023-0071) | `.cargo/audit.toml` still ignores it | ~200 (aws-lc-rs wrapper) | ★★★★ | `WS-ADVISORY-CLEANUP` |
| G-9 | Anonymous cross-platform SYSVOL SMB walk | `crates/sysvol` has fs/UNC scanner but no `smb2-client`-driven anonymous share walk | ~250 | ★★★ | `WS-SYSVOL-ANON` |
| G-10 | Coerce scan-all mode | `ms-coerce 0.1.0` has vector table; no `attack coerce --scan-all` verb wraps it | ~100 | ★★★ | `WS-COERCER` |
| G-11 | `enum web --fingerprint` beyond `/certsrv` + `/wsman` | net.rs probes only 2 endpoints; RDWeb/ADFS/OWA/EWS/SCCM absent | ~200 | ★★ | `WS-WEB-FP` |
| G-12 | Receipt schema + CI validator | `docs/receipts/README.md` sets naming; no schema + no `scripts/validate_receipt.py` | ~150 | ★★ | `WS-RECEIPT-SCHEMA` |
| G-13 | Cascade rehearsal dry-run | `docs/PUSH_1.4.9.md` runbook exists; no scripted per-crate `cargo publish --dry-run` in CI | ~100 | ★★★ | `WS-CASCADE-REHEARSAL` |
| G-14 | LDAPS channel-binding (RFC 5929) | **HYPOTHESIS.** 1.4.9 receipts show `AcceptSecurityContext data 52e`; code interprets `52e` as invalid-creds. Need packet capture against 2019/2022/2025 to prove CBT enforcement before pricing. Do NOT block ship-gate on this until evidence justifies it. | tbd | tbd | `WS-LDAPS-CB-INVESTIGATE` |

Explicitly **not** on this list (previously claimed as gap, actually present):
- DNS SRV enum — `discovery.rs` draft exists (needs G-1 to become live).
- SMB signing probe — `enum net` line 100.
- Anonymous scan mode — `attacks/scan_anonymous.rs` 348 LOC.
- SAMR enum via SMB pipe — `attacks/samr.rs` + `dcerpc 0.2.8`'s
  `SamrClient` (no `ms-samr` sibling needed).
- ADIDNS enum via LDAP — `enums/dns.rs`.
- HTTP fingerprint of `/certsrv` + `/wsman` — `enum net`.
- MachineAccountQuota read — collector line 925 (baseline for noPac
  assessment).
- Cross-platform TLS — `tokio-rustls 0.26` + `rustls 0.23` in cli/.

## Workstreams (locked defaults)

Priorities are release-gate-derived. **P0 = required for score to
stop decreasing.** No P0 can be deferred to 1.5.1.

### WS-FOUNDATION-INTEGRATE (P0)
Track `scope.rs` / `discovery.rs` / `blackbox.rs`. Add `mod` declarations
in each `lib.rs`. Add `ipnet` + `hickory-resolver` to workspace deps.
Fix BF-3 (unified `contains(target)` that resolves identity forms
before applying excludes). Fix BF-4 (enforce `max_hosts` +
`max_duration_secs` in runner path; enforce `allow_impact` +
`allow_spoof` before `PostCred` / spoof-class checks). Fix BF-5
(gate `PostCred` behind capability presence). Add integration tests
that exercise each policy field. Land `cli/tests/live_safe.rs` +
`live_impact.rs` under formatted state; wire behind `--ignored`
gates + env-var opt-in so CI stays green offline.
**Verifiable close:** `cargo build --workspace` compiles the three
new files; `cargo test --workspace` includes ≥ 12 new tests; a
capability-missing `PostCred` selection returns `Err`.

### WS-FEATURE-MATRIX (P0)
Split `--all-features` so `tls-native` and `tls-rustls` cannot both
activate. Make one a workspace-default feature; make the other
mutually-exclusive via `#[cfg]` + a compile-time diagnostic. Add a CI
job that runs `cargo check --workspace --all-features` and blocks red.
**Verifiable close:** the new CI job green.

### WS-LDAP-INTEGRITY (P0)
Refuse `ldap.simple_bind` unless (a) LDAPS is verified end-to-end or
(b) SASL sealing / signing is negotiated. Downgrade to hard error the
plaintext-389 read path. Add LDAP response-size + entry-count +
per-call deadline budgets to match WinRM (BF-7).
**Verifiable close:** an integration test against a fake LDAP server
that offers only plaintext-389 returns `Err`; a fuzz target exercising
budget rejection lives under `fuzz/fuzz_targets/`.

### WS-SECRET-BOUNDARY (P0)
Wrap `decrypt_cpassword` output in `SecretString` at the crate
boundary. Add a `#[derive(Debug)]` compile-fail test that ensures GPP
plaintext cannot be embedded raw in `Finding` / report structs. Move
ccache + hashcat-input + GPP-dump writes to a `write_secret_artifact`
helper that enforces `0o600` + POSIX / Windows-DACL parity.
**Verifiable close:** grep of `String::from(decrypted)` in report
crate returns 0; `find_debug_leaks` compile-fail test passes.

### WS-OUTPUT-SANITIZE (P0)
Add `sanitize_terminal_output` that strips C0 (except `\n\t`), CSI
sequences, and OSC sequences from network-derived strings before
they hit stdout / stderr / Finding.detail / report body. Wire at
every terminal-writing site + at JSON/HTML/MD/TXT report builders.
**Verifiable close:** a unit test feeding `"\x1b[31m\x07inject"`
into every writer path shows the escape stripped.

### WS-SYSVOL-BUDGETS + WS-SYSVOL-ANON (P1)
Budgets first (max file size, max recursion depth, max cpassword-
match count). Then extend the sysvol walker with `smb2-client`
null-session anonymous walk — filesystem/UNC scanner exists, anon-SMB
does not.
**Verifiable close:** a synthetic 100 MB `Groups.xml` gets refused;
a live-tested anon walk against Server 2019 succeeds against a share
configured for null access and refuses cleanly against a share that
isn't.

### WS-DEPS-MAJORS (P1)
`picky-krb 0.9 → 0.12` (~30 mechanical edits in `crates/kerberos/
src/tgs.rs` + follow-on in `pac.rs` / `unpac.rs`). Coupled with
`picky-asn1-x509 0.13 → 0.15.4`. Land RustCrypto ecosystem bump
(`md-5 0.11`, `md4 0.11`, `sha2 0.11`, `rc4 0.2`, `rand 0.10`, `des 0.9`)
in a second commit. Retire `catch_unwind` around `decrypt_ticket_pac` +
drop `AES_MIN = 44` / `RC4_MIN = 40` outer-bound workarounds. Restore
the retired `pac_parse_full` fuzz target. Fuzz-non-regression for 3
nights before removing mitigation notes.
**Verifiable close:** fuzz job runs `pac_parse_full` clean for 3
consecutive nights; BUG-19 line in `docs/PLAN_1.5.0.md` moves to
CHANGELOG as closed.

### WS-ADVISORY-CLEANUP (P1)
Fork `ms-icpr` in-tree as `crates/ms-icpr` + `[patch.crates-io]`.
Replace `rsa 0.9` with `aws-lc-rs` RSA API. Remove
`RUSTSEC-2023-0071` from `.cargo/audit.toml` + `deny.toml`. Add
`docs/adr/0002-remove-rsa-0.9.md`.
**Verifiable close:** `cargo tree -i rsa --locked` returns 0 hits;
`cargo audit` passes zero-ignores.

### WS-COERCER + WS-WEB-FP (P2)
`attack coerce --scan-all` wraps `ms-coerce`'s vector table. `enum web
--fingerprint` extends net.rs's 2-endpoint probe to
{`/`, `/certsrv/`, `/RDWeb/`, `/adfs/ls/`, `/FederationMetadata/2007-06/`,
`/EWS/Exchange.asmx`, `/owa/`, `/CCM_Client/`, `/CertEnroll/`,
`/Autodiscover/Autodiscover.xml`}. HTTPS via existing `tokio-rustls
0.26`. Zero new deps.
**Verifiable close:** each verb has ≥ 3 unit tests + wire-format
snapshots.

### WS-RECEIPT-SCHEMA + WS-CASCADE-REHEARSAL (P2)
`docs/receipts/SCHEMA.md` names required fields; `scripts/
validate_receipt.py` parses + exits non-zero on schema drift; new CI
job blocks red. `scripts/cascade_dry_run.sh` computes bottom-up
publish order from `cargo metadata`, runs `cargo publish --dry-run`
per crate on `workflow_dispatch`. `docs/CASCADE_1.5.0.md` auto-
generated.
**Verifiable close:** both CI jobs green on `main` for 3 consecutive
runs.

### WS-CLI-SHRINK (P2)
Move ~5000 LOC of orchestration from `cli/` into `adhammer-sdk` so
the SDK is a real orchestration API not a pub-use façade. Land AFTER
`WS-FOUNDATION-INTEGRATE` so new verbs migrate at the same time.
Deliverable: one lib-only `examples/scan_no_binary.rs` that runs a
scan without invoking the binary.
**Verifiable close:** `cargo run --example scan_no_binary` succeeds
end-to-end against the offline test fixture.

### WS-FUZZ-DEEP (P2)
Add `.github/workflows/fuzz-deep.yml` — nightly 03:00 UTC, 30 min /
target, coverage-guided, seeded from `fuzz/corpus/<target>/seeds/`,
corpus stored as workflow artifact. Extend fuzz surface with
`pkinit_as_rep`, `ldap_entry`, `dpapi_ng` targets.
**Verifiable close:** 7 consecutive nights green after `WS-DEPS-MAJORS`
lands.

### WS-MSRV-POLICY (P2)
`docs/MSRV.md` — workspace floor "stable N-3"; sibling-crate floor
per-crate in `Cargo.toml`. Extend `msrv` CI job to verify per-crate
floor. Populate rows in `docs/STABILITY.md`.
**Verifiable close:** CI matrix at declared floor green.

### WS-LDAPS-CB-INVESTIGATE (P2 — investigation only)
Capture LDAPS traffic against 2019 / 2022 / 2025 lab DCs with
`--bind-user` set. Confirm whether `data 52e` originates from CBT
enforcement or from something else (Kerberos PA, LDAP signing, etc.).
If CBT: file `WS-LDAPS-CB` implementation workstream in 1.5.1 plan
with real effort estimate + `docs/adr/0003-ldaps-cbt.md`. If NOT
CBT: document root cause + close as "no code change owed."
**Verifiable close:** one packet-trace receipt + one decision doc.

## Non-goals for 1.5.0
- Azure / Entra ID / M365 — permanent NO.
- Persistence framework (Skeleton-Key / SSP-inject / DSRM-hijack) —
  permanent NO per `feedback-adhammer-hard-rules`.
- GUI — TUI is the operator-in-the-loop story.
- C2 features — NO_C2 stance.
- AI features — WS-21/22 rejected.
- `ms-samr` sibling crate — `dcerpc 0.2.8`'s `SamrClient` is sufficient;
  extend transport / opnums in `dcerpc` if needed rather than spawn.
- `mitm6` / DHCPv6 WPAD — deferred to 1.5.1; needs new raw-socket
  sibling.
- Black-box one-command orchestrator (`black-box` verb) — deferred to
  1.5.1; requires WS-FOUNDATION-INTEGRATE + WS-COERCER + WS-WEB-FP
  landed as building blocks first.
- LDAPS-CB implementation — 1.5.1 candidate ONLY if WS-LDAPS-CB-
  INVESTIGATE proves the hypothesis.

## Ship-gate — canonical release rubric

Release blocks until every row below is green.

| Gate | Weight | State |
|---|---|---|
| `cargo test --workspace` green on ubuntu + macos + windows | required | ✓ today |
| `cargo clippy --workspace --all-targets -- -D warnings` green | required | ✓ today |
| `cargo build` at MSRV 1.88 green | required | ✓ today |
| `cargo fmt --all --check` green | required | ✗ today (CI-FAIL-2) |
| `cargo check --workspace --all-features` green | required | ✗ today (CI-FAIL-1) |
| `cargo audit` 0 vulnerabilities + 0 ignores | 8 | 0 (rsa 0.9 ignore) |
| `cargo deny check` 0 warnings + 0 skips | 4 | 0 (transitive dupes) |
| Fuzz job green 7 consecutive nights | 5 | 0 (BUG-19 outstanding) |
| Reproducible-build attestation green | 4 | 0 |
| Signed evidence bundle (SBOM + sigstore + receipts + fuzz summary) | 4 | 0 |
| Foundation integrated + policy-enforced tests | 5 | 0 |
| DNS / RootDSE / SMB null scope-driven | 5 | 0 |
| Anonymous SMB SYSVOL walk cross-platform | 3 | 0 |
| HTTP fingerprint on 10 AD web endpoints | 3 | 0 |
| Coerce scan-all mode | 3 | 0 |
| SNMP + web fingerprint at range | 3 | ★ partial |
| Black-box orchestrator ties them into one run | 3 | 0 |
| Every 1.4.9 authed verb still passing | 8 | ✓ today |
| LDAPS-CB (IF INVESTIGATE justifies) | 5 | pending investigation |
| picky-krb 0.9→0.12 + BUG-19 retired | 5 | 0 |
| NTDS.dit offline (needs external `ese-parser 0.2`) | 4 | 0 |
| noPac CVE-2021-42278 | 3 | 0 |
| SDK is real orchestration API not façade | 5 | 0 |
| CLI-shrink into SDK done | 4 | 0 |
| Per-crate MSRV published | 3 | 0 |
| Receipt schema + validator in CI | 4 | 0 |
| CASCADE-REHEARSAL green | 5 | 0 |
| Cross-version live-DC receipts approved (2019 + 2022 + 2025) | 4 | ★ 1.4.9 partial |

**Verifiable ship target:** 80/100 (with LDAPS-CB decided one way or
the other, WS-FOUNDATION-INTEGRATE + all P0/P1 + WS-COERCER +
WS-WEB-FP landed, WS-CLI-SHRINK optional). Higher requires more of P2
+ the calendar-time / external-audit ceiling items.

## Release cadence

- **1.5.0-alpha.1** — all P0 landed; `cargo fmt --check` and
  `cargo check --all-features` green.
- **1.5.0-beta.1** — WS-DEPS-MAJORS + WS-ADVISORY-CLEANUP green;
  WS-FUZZ-DEEP running for 3 nights.
- **1.5.0-rc.1** — WS-CASCADE-REHEARSAL green on the rc commit;
  WS-RECEIPT-SCHEMA validator green; every P1 landed.
- **1.5.0** — every ship-gate row above ≥ target weight + operator
  approves cascade-publish.

## Bug-carry (append-only during shakedown)

### CI-FAIL-1 — `--all-features` breaks ldap3
**State:** open. **Owner:** WS-FEATURE-MATRIX. **Same-cycle.**

### CI-FAIL-2 — `cargo fmt --check` fails on live-test files
**State:** open. **Owner:** WS-FOUNDATION-INTEGRATE (lands the files
formatted). **Same-cycle.**

### BUG-19 — `pac_credential_info` fuzz-found panic (picky-krb class)
**State:** open, production-mitigated only. **Owner:**
WS-DEPS-MAJORS. `catch_unwind` guard around `decrypt_ticket_pac`
mitigates production callers; the fuzz build uses `-C panic=abort`
which cannot catch the panic, so fuzz stays red until picky-krb 0.12
lands. Do not conflate "prod mitigated" with "fuzz clean."

### CI-1 — package-check under all-local (from 1.4.9)
**State:** mitigated by gate-on-tag + `manifest-sanity` job.
**Owner:** closes automatically when WS-CASCADE-REHEARSAL lands.

## Notes on superseded docs
- `docs/PLAN_1.5.0_REVAMP.md` — kept in-tree with superseded header;
  its 5 principles ("start from scope", consent gates, low-impact
  first, reuse authed stack only when prereqs met, evidence over
  guaranteed-DA) are now the framing of this canonical plan.
- `docs/PLAN_1.5.0_100_100_ANALYSIS.md` — kept in-tree with
  superseded header; its 4-axis score model is now this plan's
  §"Score model" (baseline recomputed against verified gates).
- `ADHAMMER_BLACKBOX_RESEARCH.md` (Documents root, external to repo) —
  research doc from 2026-09-01; its 14-workstream list was accurate
  at write time but ~half of the listed gaps have since been filled
  in draft or integrated form. This canonical plan's §"True gap-list"
  reflects the code state as of 2026-09-02.
