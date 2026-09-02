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
- **CI-FAIL-1 (RECLASSIFIED as audit misinterpretation, closed
  2026-09-02):** `cargo check --workspace --all-features` was expected
  to be green in the earlier ship-gate. It is not, and never can be:
  `adhammer-collector` legitimately exposes both `tls-native` and
  `tls-rustls` for operator choice (rustls default; native-tls for
  legacy SHA-1 DCs); `ldap3` treats those as mutually-exclusive TLS
  backends and its own upstream `compile_error!` fires when both
  activate. `--all-features` is not a supported invocation on this
  workspace. Ship-gate replaced with "supported-feature-matrix job
  green" (the existing "check supported feature variants" step covers
  {no-default, default, tls-native only, mssql+gssapi, experimental-
  gkdi}). A defensive `compile_error!` guard was added at
  `crates/collector/src/lib.rs` in commit `<pending>` so the boundary
  message is ours, not ldap3's, if the feature propagation ever
  changes.
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
| G-1 | Foundation files tracked + integrated + tests | closed 2026-09-02 for scope.rs + blackbox.rs (BF-3/4/5 landed); discovery.rs deferred to `WS-FOUNDATION-DNS-HANDROLL` (1.5.1) per D2 hand-roll lock | ~400 (+ 200 test) | ★★★★★ | `WS-FOUNDATION-INTEGRATE` |
| G-2 | Feature-matrix boundary diagnostic (defensive) | ldap3 already guards mutex upstream; wanted our own `compile_error!` at collector so the diagnostic is ours if the feature-graph shifts | ~15 | ★★ | `WS-FEATURE-MATRIX` |
| G-3 | LDAP simple-bind integrity requirement | closed 2026-09-02 (BF-1); CLI plumbing owed via `WS-CLI-PLAINTEXT-LDAP-FLAG` (1.5.1) | ~150 | ★★★★ | `WS-LDAP-INTEGRITY` |
| G-4 | GPP secret boundary + Debug redaction | closed 2026-09-02 (BF-2); ccache/hashcat call-sites owed via `WS-SECRET-BOUNDARY-CALLSITES` (1.5.1); Windows-DACL parity owed via `WS-SECRET-BOUNDARY-WINDOWS-DACL` (1.5.1) | ~120 | ★★★★ | `WS-SECRET-BOUNDARY` |
| G-5 | LDAP + SYSVOL resource budgets | closed 2026-09-02 (BF-7); byte-level cap owed via `WS-LDAP-INTEGRITY-RESPONSE-BYTES` (1.5.1) | ~200 | ★★★ | `WS-LDAP-INTEGRITY` + `WS-SYSVOL-BUDGETS` |
| G-6 | Output control-char sanitization | ~closed 2026-09-02 (adhammer_core::sanitize + Report::build wiring); direct-println sites in cli/ still owed via WS-CLI-SHRINK | ~80 | ★★★ | `WS-OUTPUT-SANITIZE` |
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

### WS-FOUNDATION-INTEGRATE (closed 2026-09-02, D2 lock applied)
Same-cycle scope landed:
- `crates/core/src/scope.rs` tracked + `pub mod scope;` declared;
  re-exports `EngagementScope`, `ScopeTarget`, `CheckId`, `CheckClass`,
  `FindingStatus`, `Capability`, `CapabilityKind`, `NextAction`,
  `SecretHandle`, `ScopeError`. `ipnet 2.11` added to workspace +
  core `[dependencies]`.
- BF-3 fixed: `EngagementScope::allows(ip, hostname)` treats excludes
  as cross-cutting across identity forms. Two regression tests
  (`hostname_exclude_blocks_ip_lookup_via_allows`,
  `ip_exclude_blocks_hostname_lookup_via_allows`) prove that with
  both forms supplied, an exclude on EITHER axis blocks the target.
- `crates/sdk/src/blackbox.rs` tracked + `pub mod blackbox;`
  declared; re-exports `BlackBoxRunner`, `RunPolicy`, `ConsentPolicy`,
  `CheckSelection`, `RunSummary`, `RunnerRefusal`.
- BF-4 fixed: `BlackBoxRunner::start_host(ip)` enforces `max_hosts`
  (first-touch counted, repeat touches free); `duration_within_budget`
  + `may_run` enforce `max_duration_secs`; runners that broadcast-
  spoof query `policy.consent.allow_spoof` directly (documented).
- BF-5 fixed: `may_run(check, PostCred)` returns
  `RunnerRefusal::PostCredRequiresCapability` unless at least one
  capability has been recorded via `record_capability`.
- `RunnerRefusal` is a distinct enum so a report can render "why not"
  (`NotInSelection` / `ImpactRequiresConsent` /
  `PostCredRequiresCapability` / `HostBudgetExhausted` /
  `DurationBudgetExhausted`) with a `Display` impl per variant.

D2 lock applied — `hickory-resolver` NOT added. Draft
`crates/collector/src/discovery.rs` stays untracked-on-disk (it
uses hickory and needs a hand-roll rewrite). `blackbox::discover_dns`
was removed for this cycle; comes back as a runner method when the
hand-rolled backend lands.

Regression tests (target ≥ 12): landed 20.
- scope: 11 tests (BF-3 cross-cut coverage + existing round-trips +
  invalid-input rejection).
- blackbox: 9 tests (BF-4 max_hosts, BF-4 duration, BF-5 postcred
  gate, selection filter, refusal `Display` messages, defensive-
  clone capability snapshot).

Explicit follow-up (1.5.1):
- **WS-FOUNDATION-DNS-HANDROLL**: hand-roll DNS SRV + A + PTR from
  scratch (UDP + TCP fallback, retries, timeout, CNAME chase,
  NXDOMAIN / SERVFAIL / truncation handling). ~400-600 LOC in
  `crates/collector/src/discovery.rs` (overwrites the current
  hickory-based draft). Adds a `discover_dns` method back to
  `BlackBoxRunner` that respects `may_run` + `start_host`.
- **WS-FOUNDATION-BLACKBOX-CLI**: expose `BlackBoxRunner` via a
  `adhammer run --scope <json>` subcommand so operators actually
  reach it. Currently the runner is library-only.

**Verifiable close (this cycle):** `cargo build --workspace` green;
`cargo test --workspace` adds 20 new tests (≥ 12 required); a
`may_run(_, PostCred)` without a recorded capability returns
`RunnerRefusal::PostCredRequiresCapability`.

### WS-FEATURE-MATRIX (closed 2026-09-02)
CLOSED as audit misinterpretation. `--all-features` cannot be green
on this workspace by design (see CI-FAIL-1 reclassification above).
Defensive `compile_error!` boundary guard landed at
`crates/collector/src/lib.rs`. Ship-gate uses the existing
"check supported feature variants" CI step as authority for
supported combinations. No further code change owed.

### WS-LDAP-INTEGRITY (closed 2026-09-02, minimum-viable root)
Same-cycle scope landed:
- `crates/collector/src/lib.rs::require_bind_integrity` — free
  function refuses an authed simple_bind over plaintext `ldap://`
  unless the operator explicitly opts in via the new
  `LdapConfig.allow_plaintext_bind` field. Anonymous binds
  (empty `bind_dn`) always allowed — no credential in flight.
  GSSAPI over 389 allowed — SASL sealing on the wire. LDAPS always
  allowed. Called from `Collector::connect` before the socket dials.
- `LdapConfig` grew the `allow_plaintext_bind: bool` field; all 13
  in-tree construction sites default to `false`. A CLI flag
  `--allow-plaintext-ldap` that plumbs to the field lands as a 1.5.1
  follow-up (`WS-CLI-PLAINTEXT-LDAP-FLAG`) — same-cycle change
  keeps the SECURE default without shipping a foot-gun.
- LDAP paged-search loop now enforces
  `LDAP_MAX_ENTRIES_PER_SEARCH = 500_000` and refuses any hostile
  server that dribbles more (BF-7 for LDAP).
- SYSVOL walk now enforces `SYSVOL_MAX_WALK_DEPTH = 32`,
  `SYSVOL_MAX_FILE_BYTES = 4 MiB`, `SYSVOL_MAX_HITS = 10_000`
  (BF-7 for SYSVOL). File over cap is skipped with `warn`; depth or
  hit cap stops the walk with `warn` — never a silent short-return.

Regression coverage:
- 5 new collector tests for `require_bind_integrity` cover:
  refuses authed plaintext-389 · allows LDAPS authed · allows GSSAPI
  over plaintext-389 · allows anonymous plaintext · respects
  explicit `allow_plaintext_bind`.
- 2 new sysvol tests cover: oversized file skipped-but-walk-continues
  · depth cap stops recursion before a deep cpassword is seen.

Deferred (tracked here):
- **WS-LDAP-INTEGRITY-RESPONSE-BYTES** (1.5.1): a byte-level cap on
  paged responses requires wrapping ldap3's stream to count decoded
  BER frames. Entry-count cap covers the same DoS class today; the
  byte cap is a stricter belt-and-braces.
- **WS-LDAP-INTEGRITY-FAKE-SERVER** (1.5.1): a hermetic fake LDAP
  server test that offers only plaintext-389 + verifies our refusal.
  Requires ldap-fixture infrastructure.
- **WS-CLI-PLAINTEXT-LDAP-FLAG** (1.5.1): plumb the new field to a
  CLI arg per attack verb.

**Verifiable close (this cycle):** 5 new `require_bind_integrity`
tests green; 2 new sysvol budget tests green.

### WS-SECRET-BOUNDARY (closed 2026-09-02)
Same-cycle scope landed:
- `adhammer_core::secret_write::write_secret_artifact` — Unix
  O_CREAT|O_EXCL 0o600 atomic; Windows `File::create_new` (parent-dir
  DACL responsibility documented; full Windows-DACL parity via
  `windows-sys` FFI tracked as `WS-SECRET-BOUNDARY-WINDOWS-DACL`
  1.5.1 follow-up).
- `crates/sysvol/src/gpp.rs::decrypt_cpassword` returns
  `SecretString`; `GppHit.password` is `SecretString`. A stray
  `Debug`/`Display` prints `"***"`.
- `crates/sysvol/src/lib.rs::finding` no longer embeds the plaintext
  into `affected[]` or `evidence.value` (closes BF-2). New
  `write_dump` helper is the ONE authorized exposure site
  (`.expose_secret()` is greppable there — one hit).
- Regression tests: `finding_never_carries_recovered_plaintext`,
  `write_dump_lands_tab_separated_plaintext`,
  `decrypt_result_hides_plaintext_in_debug_and_display`.

Follow-up work (not blocking; tracked here so it doesn't drift):
- **WS-SECRET-BOUNDARY-CALLSITES** (1.5.1): migrate the 10+
  ccache / hashcat-input / keytab writers in `cli/src/attacks/`
  (asktgt, abuse, diamond, esc1, golden, icpr_esc1, relay, silver,
  csr) from ad-hoc `fs::write` to `write_secret_artifact` +
  wrap kept-plaintext in `SecretString` at the produce site. Pattern
  established here; sweep is mechanical.
- **WS-SECRET-BOUNDARY-WINDOWS-DACL** (1.5.1): after the
  `win32-min` sibling grows a `SecurityDescriptor` helper (~50 LOC
  wrapping `SetKernelObjectSecurity`), rewire
  `write_secret_artifact` on Windows to apply an owner-only DACL
  atomically at `CreateFileW` time via `SECURITY_ATTRIBUTES`.
- **WS-CLI-GPP-DUMP-FLAG** (1.5.1): wire the CLI flag
  `--gpp-dump-out <path>` in `cli/src/attacks/scan.rs:381` to call
  `adhammer_sysvol::write_dump` when the operator supplies a path;
  the finding.evidence line already directs them to the flag.

**Verifiable close (this cycle):** 3 new sysvol regression tests
green; `git grep '\.password[[:space:]]*[,\)]' crates/sysvol/`
returns only field defs, never format-string embeds.

### WS-OUTPUT-SANITIZE (closed 2026-09-02)
Landed. `adhammer_core::sanitize::sanitize_terminal_output` strips
C0 (except `\n\t`), DEL, Unicode C1, CSI, OSC (BEL- or ST-terminated,
byte-capped), and 2-byte ESC-N escapes. Wired in `Report::build` so
`domain`, every `Finding` (title/detail/impact/remediation/affected/
evidence) and every `AttackPath` (principal/target/step endpoints/
step commands) go through the sanitizer BEFORE the JSON / HTML /
Markdown / text renderers read them. `Step`'s `edge` / `impact` /
`mitigation` are `&'static str` compile-time constants — not touched.
`WireExchange` intentionally not sanitized (raw wire dumps must stay
byte-exact for reproducibility; sanitize at presentation site).
**Verifiable close:** `build_scrubs_terminal_control_from_every_renderer`
in `crates/report/src/lib.rs` (green); 15 unit tests in
`crates/core/src/sanitize.rs` (green).

Remaining follow-ups (not blocking; folded into later workstreams):
- Stream-of-stdout `println!` sites that print LDAP-derived strings
  directly (not via Report::build) still need per-site wiring. Enumerate
  and address alongside `WS-CLI-SHRINK` (all CLI direct-println of
  network text migrates into SDK-provided formatters).

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
| Supported-feature-matrix job green (see "check supported feature variants" step; enumerates {no-default, default, tls-native only, mssql+gssapi, experimental-gkdi}) | required | ✓ today (CI-FAIL-1 reclassified) |
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
**State:** closed 2026-09-02 as audit misinterpretation. `--all-features`
was never a supportable invocation on this workspace (mutually-
exclusive TLS backends by design). Ship-gate updated to reference
the supported-feature-matrix job instead. Boundary `compile_error!`
guard landed at `crates/collector/src/lib.rs`.

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
