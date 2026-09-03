# ADhammer 1.4.10 — hardening patch release (all local)

Written 2026-09-02. Split out from `docs/PLAN_1.5.0.md` because these
workstreams are BUG-fix / defence-in-depth for code that already
shipped in 1.4.9 — not new capability. Version discipline:
`1.4.9 → 1.4.10` = patch release, no feature additions, no operator-
observable behaviour change beyond stricter refusal messages + fewer
leaked bytes.

## Post-release state — 2026-09-03

The historical plan below records the local development policy used while
1.4.10 was being prepared. Current distribution truth supersedes that policy:

- **Final alignment (2026-09-03):** `v1.4.10` was retagged to `d0791e4` so
  the tag source carries the finished secret-writer hardening, approved
  receipts, green ledger/CI, and the Intel macOS build leg. The GitHub
  release rebuilt from that tag (5 binaries incl. Intel x64).
- **crates.io cascade published (2026-09-03):** all 12 crates at 1.4.10,
  bottom-up (core → secrets/ldap/graph/sysvol/kerberos/collector/bloodhound
  → checks → report → sdk → adhammer). `cargo install adhammer` now
  installs 1.4.10. Distribution is fully aligned: GitHub source + tag +
  release binaries + crates.io all at 1.4.10.
- Historical note: the original tag pointed to `b98a73b` (red ledger CI +
  pending-status receipt JSON); superseded by the `d0791e4` retag above.

### Historical preparation policy

The rule while this batch was being prepared was: LOCAL only. No `cargo publish`, no
`git push origin main`. When this batch is ready to publish, the
operator triggers the cascade explicitly. Every commit landed under
these workstreams stays local until then.

## Origin

Audit 2026-09-02 surfaced 8 behavioural findings (BF-1..8) + 2 CI
failures (CI-FAIL-1, CI-FAIL-2) + 1 foundation-drift finding (G-1).
Every item in that list is a defect against 1.4.9's tree, not a
missing 1.5.0 capability. Correct home is a patch release.

## Landed workstreams

### CI-FAIL-2 (closed 2026-09-02) — track `cli/tests/live_{safe,impact,common}`

Live-DC integration test files were on disk in untracked state since
2026-09-01. `cargo fmt --check` failed because `live_safe.rs:120`
needed a multi-line reformat. Landed under formatted state after
grep-verifying against `.githooks/leak-terms.txt` (0 matches — all
creds are runtime-env-gated, docstrings use RFC1918 placeholders).
All tests are `#[ignore]`d and additionally gated on `ADH_DC` env
var; impact tests further require `ADH_IMPACT=1`. `cargo test` stays
hermetic and green offline.

**Verifiable close:** `cargo fmt --all --check` returns 0.

### WS-FEATURE-MATRIX (closed 2026-09-02 — audit misinterpretation)

`cargo check --workspace --all-features` was expected to be green in
the earlier ship-gate. It is not, and never can be: `adhammer-collector`
legitimately exposes both `tls-native` and `tls-rustls` for operator
choice (rustls default; native-tls for legacy SHA-1 DCs); `ldap3`
treats them as mutually-exclusive TLS backends and its own upstream
`compile_error!` fires when both activate. `--all-features` is not a
supported invocation on this workspace.

Ship-gate replaced with "supported-feature-matrix job green" (the
existing "check supported feature variants" step covers {no-default,
default, tls-native only, mssql+gssapi, experimental-gkdi}). A
defensive `compile_error!` guard was added at
`crates/collector/src/lib.rs` so the boundary message is ours if the
feature propagation ever changes.

**Verifiable close:** the 5 supported feature combos compile clean;
ldap3's own upstream guard still fires cleanly for the mutex combo.

### WS-OUTPUT-SANITIZE (closed 2026-09-02) — BF-8

`adhammer_core::sanitize::sanitize_terminal_output` strips C0 (except
`\n\t`), DEL, Unicode C1, CSI, OSC (BEL- or ST-terminated, byte-capped),
and 2-byte ESC-N escapes. Wired in `Report::build` so `domain`, every
`Finding` (title/detail/impact/remediation/affected/evidence) and
every `AttackPath` (principal/target/step endpoints/step commands) go
through the sanitizer BEFORE the JSON / HTML / Markdown / text
renderers read them. `Step`'s `edge` / `impact` / `mitigation` are
`&'static str` compile-time constants — not touched. `WireExchange`
intentionally not sanitized (raw wire dumps must stay byte-exact for
reproducibility; sanitize at presentation site if the wire log is ever
rendered inside a report body).

**Verifiable close:** `build_scrubs_terminal_control_from_every_renderer`
in `crates/report/src/lib.rs` (green); 15 unit tests in
`crates/core/src/sanitize.rs` (green).

Remaining follow-ups (fold into 1.5.0 WS-CLI-SHRINK):
- Stream-of-stdout `println!` sites that print LDAP-derived strings
  directly (not via Report::build) still need per-site wiring.

### WS-SECRET-BOUNDARY (closed 2026-09-02) — BF-2

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

Follow-up work (1.5.1, tracked so it doesn't drift):
- **WS-SECRET-BOUNDARY-CALLSITES**: migrate the 10+ ccache /
  hashcat-input / keytab writers in `cli/src/attacks/` (asktgt,
  abuse, diamond, esc1, golden, icpr_esc1, relay, silver, csr) from
  ad-hoc `fs::write` to `write_secret_artifact` + wrap
  kept-plaintext in `SecretString` at the produce site.
- **WS-SECRET-BOUNDARY-WINDOWS-DACL**: after the `win32-min` sibling
  grows a `SecurityDescriptor` helper (~50 LOC wrapping
  `SetKernelObjectSecurity`), rewire `write_secret_artifact` on
  Windows to apply an owner-only DACL atomically at `CreateFileW`
  time via `SECURITY_ATTRIBUTES`.
- **WS-CLI-GPP-DUMP-FLAG**: wire the CLI flag `--gpp-dump-out <path>`
  in `cli/src/attacks/scan.rs:381` to call
  `adhammer_sysvol::write_dump` when the operator supplies a path;
  the finding.evidence line already directs them to the flag.

**Verifiable close:** 3 new sysvol regression tests green;
`git grep '\.password[[:space:]]*[,\)]' crates/sysvol/` returns only
field defs, never format-string embeds.

### WS-LDAP-INTEGRITY (closed 2026-09-02) — BF-1 + BF-7

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

Deferred (1.5.1):
- **WS-LDAP-INTEGRITY-RESPONSE-BYTES**: a byte-level cap on paged
  responses requires wrapping ldap3's stream to count decoded BER
  frames. Entry-count cap covers the same DoS class today; the byte
  cap is a stricter belt-and-braces.
- **WS-LDAP-INTEGRITY-FAKE-SERVER**: a hermetic fake LDAP server
  test that offers only plaintext-389 + verifies our refusal.
- **WS-CLI-PLAINTEXT-LDAP-FLAG**: plumb the new field to a CLI arg
  per attack verb.

**Verifiable close (this cycle):** 5 new `require_bind_integrity`
tests green; 2 new sysvol budget tests green.

### WS-FOUNDATION-INTEGRATE (closed 2026-09-02, D2 lock applied) — G-1 + BF-3 + BF-4 + BF-5

Note: types LAND in 1.4.10; the observable no-cred discovery capability
they support LANDS in 1.5.0. The type surface is safe to ship in a
patch release because it is not reachable via any CLI verb yet.

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

D2 lock (docs/PLAN_1.5.0.md) applied: `hickory-resolver` NOT added.
Draft `crates/collector/src/discovery.rs` stays untracked-on-disk (it
uses hickory and needs a hand-roll rewrite). `blackbox::discover_dns`
was removed for 1.4.10; comes back as a runner method when the
hand-rolled backend lands in 1.5.0.

Regression tests: 20 landed.
- scope: 11 tests (BF-3 cross-cut coverage + existing round-trips +
  invalid-input rejection).
- blackbox: 9 tests (BF-4 max_hosts, BF-4 duration, BF-5 postcred
  gate, selection filter, refusal `Display` messages, defensive-
  clone capability snapshot).

Follow-ups (1.5.0 scope — those workstreams turn the foundation code
into observable capability):
- **WS-FOUNDATION-DNS-HANDROLL** (1.5.1 candidate under docs/PLAN_1.5.0.md):
  hand-roll DNS SRV + A + PTR from scratch (~400-600 LOC in
  `crates/collector/src/discovery.rs`, overwrites the current
  hickory-based draft). Adds a `discover_dns` method back to
  `BlackBoxRunner` that respects `may_run` + `start_host`.
- **WS-FOUNDATION-BLACKBOX-CLI** (1.5.1): expose `BlackBoxRunner`
  via an `adhammer run --scope <json>` subcommand so operators
  actually reach it. Currently the runner is library-only.

**Verifiable close (this cycle):** `cargo build --workspace` green;
20 new tests; `may_run(_, PostCred)` without a recorded capability
returns `Err(RunnerRefusal::PostCredRequiresCapability)`.

## Ship gate for 1.4.10 (verified 2026-09-02 — all green locally)

| Row | Verified state |
|---|---|
| `cargo test --workspace` | ✓ 317 tests / 0 fails / 28 modules |
| `cargo clippy --workspace --all-targets -- -D warnings` | ✓ 0 errors, 0 warnings |
| `cargo build` at MSRV 1.88 | ✓ clean |
| `cargo fmt --all --check` | ✓ 0 diff lines |
| Supported-feature-matrix (5 combos) | ✓ each of `--no-default-features`, default (`tls-rustls`), `tls-native` only, `mssql+gssapi`, `experimental-gkdi` (on `adhammer-collector`) checks clean |
| `cargo deny check` (advisories · bans · licenses · sources) | ✓ all "ok" |
| `cargo audit` posture | ✓ same as 1.4.9: 1 documented ignore (`RUSTSEC-2023-0071`, rsa 0.9 Marvin sidechannel — rationale in `.cargo/audit.toml`); removal is 1.5.0 `WS-ADVISORY-CLEANUP` |
| Pre-commit hook (staged diff) | ✓ exit 0 |
| `git grep '\.password[[:space:]]*[,\)]' crates/sysvol/` (plaintext-embed check) | ✓ only field defs, no format-string embeds |
| Workspace version bumped `1.4.9 → 1.4.10` | ✓ `[workspace.package].version = "1.4.10"`; all 10 internal-dep pins updated |
| `CHANGELOG.md` `[1.4.10]` entry | ✓ landed |
| Fuzz coverage on new defence surfaces (`sanitize_terminal`, `scope_hostname`) | ✓ 2 new targets registered in `fuzz/Cargo.toml` |
| No `TODO`/`FIXME`/`XXX` in new code (sanitize / secret_write / scope / blackbox) | ✓ 0 hits |
| Cross-version live-DC receipts approved (2019 + 2022 + 2025) | ✓ `docs/receipts/1.4.10__{2019,2022,2025}.md` landed 2026-09-02; scrubber-verified (0 leak-terms matches; DES-key context-aware scrub added); `Review status: approved`; behavioral fingerprint confirmed OS mapping (2025 has no DES emission, 2019/2022 do — Server-2025 default deprecates DES from krbtgt). WS-RECEIPT-UTF8 + WS-RECEIPT-DES scrubber patches landed same-cycle. |

## Bug-carry from 1.4.9

- **CI-1** (from 1.4.9) — package-check under all-local. Mitigated
  via gate-on-tag + `manifest-sanity` job. Closes automatically
  when 1.5.0 WS-CASCADE-REHEARSAL lands. Not a 1.4.10 blocker.
- **BUG-19** (from 1.4.9) — `pac_credential_info` fuzz-found panic
  in picky-krb generic-array. Production-mitigated only via
  `catch_unwind` guard; fuzz job still red under `-C panic=abort`.
  Right fix is 1.5.0 WS-DEPS-MAJORS (picky-krb 0.9 → 0.12); not a
  1.4.10 blocker.

## Release cadence

- **1.4.10-rc.1**: all landed workstreams above tagged; ship-gate
  green.
- **1.4.10**: operator approves the local cascade + publish.

## Local commits landed this cycle (nothing pushed)

Every commit LOCAL only per operator directive. Ordered by landing:

| Commit | Workstream |
|---|---|
| `e667ab5` | CI-FAIL-2 fmt fix + track live-tests |
| `3e2404b` | WS-FEATURE-MATRIX (reclassified) |
| `8206199` | WS-OUTPUT-SANITIZE |
| `657ab2f` | WS-SECRET-BOUNDARY |
| `745b0d8` | WS-LDAP-INTEGRITY |
| `e6fbbf0` | WS-FOUNDATION-INTEGRATE |
| `b18ccd7` | label refactor 1.5.0 → 1.4.10 |
| `9581870` | 1.4.10 polish: version bump + CHANGELOG + fuzz targets + verified ship-gate |
| `<this>` | 1.4.10 live-DC receipts (2019/2022/2025) + scrubber utf-8 + DES-key context scrub |
