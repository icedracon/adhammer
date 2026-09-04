# Changelog

All notable changes to ADhammer are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); this project uses SemVer.

## [1.5.0] — 2026-09-04

Capability push: no-credential black-box AD assessment surface. Turns
adhammer from an authenticated audit tool into a first-touch engagement
tool that can characterise a domain from zero credentials — DNS
discovery → per-DC HTTP fingerprint (ADCS ESC8 relay surface, RD Web,
ADFS, OWA/EWS, SCCM) → per-DC anonymous-SMB posture (SAMR / srvsvc
sessions+shares / wkssvc / lsarpc) → per-DC anonymous SYSVOL walk for
GPP `cpassword` (MS14-025) — and adds a coercion-vector matrix + a
hashcat-mode annotator on every roast-emitted hash. See
`docs/PLAN_1.5.0.md` for the full workstream ledger and
`docs/PLAN_1.5.0_READINESS.md` for the per-workstream evidence map.

### Added — no-credential enumeration verbs

- **`adhammer run`** — hand-rolled RFC 1035 DNS resolver + scope-driven
  SRV discovery (`_ldap._tcp.dc._msdcs`, `_kerberos._tcp`, `_gc._tcp`)
  filtered to `EngagementScope` includes / excludes. No hickory / no
  external DNS crate. `WS-FOUNDATION-DNS-HANDROLL`,
  `WS-FOUNDATION-BLACKBOX-CLI`.
- **`adhammer run --web`** — chains an HTTP(S) fingerprint on every
  discovered DC IP: 13 endpoints incl. `/certsrv/` (ESC8 relay tell),
  RD Web, ADFS sign-in + FederationMetadata, OWA/EWS, Autodiscover,
  SCCM. `WS-WEB-FP`, `WS-BLACKBOX-COMPOSE`.
- **`adhammer run --deep`** — per-DC anonymous SMB posture in one null
  session per host, using the shared `probe_host` composition core.
  `WS-BB-HOST`.
- **`adhammer enum web`** — standalone version of the fingerprint.
- **`adhammer enum nullbind`** — anonymous SAMR user enumeration
  (enum4linux-style RID cycling over a `login_null` SMB session).
  `WS-FOUNDATION-NULLBIND`.
- **`adhammer enum rpc-null`** — anonymous RPC surface probe: srvsvc
  `NetSessionEnum` + wkssvc `NetrWkstaUserEnum` + lsarpc
  `LsarOpenPolicy` over one null session; reports which interfaces the
  DC exposes anonymously. `WS-BB-RPCNULL`.
- **`adhammer enum shares --anon`** — anonymous share enumeration via
  srvsvc `NetrShareEnum` level 1 (`SHARE_INFO_1`). `WS-BB-SHARES`.
- **`adhammer enum host --anon`** — single-shot enum4linux-ng-shape
  posture: SAMR users + srvsvc sessions/shares + wkssvc + lsarpc over
  ONE null session. `WS-BB-HOST`.
- **`adhammer enum sysvol`** — SYSVOL walk over SMB2 `QUERY_DIRECTORY`
  for Group Policy Preferences XML files; decrypts recovered
  `cpassword` blobs with the public MS14-025 AES key. Supports `--anon`
  (null session) and `--user` (authenticated). Recovered plaintext
  never touches stdout — write with `--dump <path>` to a
  0600 / protected-DACL secret artifact via `write_secret_artifact`.
  `WS-SYSVOL-ANON`.

### Added — active-attack surface

- **`adhammer attack coerce --scan-all`** — runs every coercion vector
  (PrinterBug / PetitPotam ×2 pipes / DFSCoerce / ShadowyCoerce) over
  one authenticated login and prints a which-fired matrix. Handles
  RPC timeout, BIND context reject, `STATUS_OBJECT_NAME_NOT_FOUND` on
  absent pipes, and BIND_NAK without panicking. `WS-COERCER`.
- **`adhammer attack roast` — hashcat-mode annotation.** Every
  Kerberoast + AS-REP hash written to stdout carries an
  `[hashglass] -m <mode> "<name>" conf=<c>` companion line on stderr;
  stdout stays hashcat-pipe-clean. `WS-HASHGLASS`.

### Changed — sibling protocol crates

- **smb2-client 0.2.1 → 0.2.3.** New `login_null` (anonymous IPC$
  session), new `list_directory` (SMB2 `QUERY_DIRECTORY`,
  `FileDirectoryInformation` class 1) with bounds-checked +
  loop-bounded parser (`NextEntryOffset` must strictly advance; a name
  overrunning its record ends parsing without OOB read; response fixed
  part guarded before direct-indexing helpers), and non-deleting
  `read_file` (distinct from the existing delete-on-close
  `read_file_delete`). Empty-name CREATE (share-root open) fix:
  `NameOffset` still points at a real byte + mandatory 1-byte buffer,
  otherwise Windows returns `STATUS_INVALID_PARAMETER`. Consumed by
  `enum sysvol` and every anon-SMB verb.
- **dcerpc 0.2.8 → 0.2.9.** New `srvsvc::NetrShareEnum` (opnum 15,
  `SHARE_INFO_1`) with the same allocation-bound discipline as the
  existing `NetSessionEnum`: attacker-controlled `EntriesRead` bounded
  against the remaining stub before `Vec::with_capacity`; hostile
  server sending `EntriesRead=0xFFFFFFFF` + truncated tail returns
  `Err(Protocol)`, not an OOM abort. Consumed by `enum shares --anon`
  and `enum host --anon`.

### Added — dependencies

- **hashglass** (workspace dep, path-only until published) —
  pentester-focused hash-type identifier; consumed by `attack roast`
  to annotate emitted hashes with their hashcat mode + confidence.
  Version pinned as `{ path = "…", version = "0.1" }` so
  `cargo deny check bans` treats it as a non-wildcard dep.
- **ipnet 2.11** (workspace dep) — CIDR + IP-address types for
  `EngagementScope` includes / excludes.

### Local-only (blocks full crates.io publish — GitHub-only release)

- Root `Cargo.toml` declares `[patch.crates-io]` overrides pointing
  `smb2-client` and `dcerpc` at their sibling worktrees. Both must be
  stripped and clean registry resolution proven before a full
  ecosystem publish, per governance §4.2 and Ecosystem-Readiness
  §C.4. `hashglass 0.1.0` is not yet on crates.io — publishing
  adhammer requires `WS-HASHGLASS-PUBLISH` to close first.

### Governance + policy formalisation

- Added `docs/AI_RELEASE_GOVERNANCE.md`, `docs/ECOSYSTEM_READINESS_100.md`,
  `AGENTS.md`, `scripts/check_release_governance.py` (CI-enforced
  guardrail against policy drift), and `docs/PLAN_1.5.0_READINESS.md`
  (per-workstream evidence map for this release).
- New sibling brainstorm `docs/BRAINSTORM_NEW_SIBLINGS.md` with the
  §6 dep-risk grid establishing hand-roll-vs-adopt discipline for
  every future external dep.
- **WS-MSRV-POLICY** — `docs/POLICY_MSRV.md` as single source of truth
  for how MSRV moves, with a `<!-- MSRV-BASELINE:X.Y -->` anchor tied
  to `[workspace.package].rust-version` in Cargo.toml.
  `scripts/check_msrv_baseline.py` fails CI on drift, forcing any
  future MSRV bump to touch the policy doc in the same reviewed diff.
  Baseline unchanged at 1.88.
- **WS-RECEIPT-SCHEMA** — `docs/receipts/schema.json` (JSON Schema
  draft-07) formalises the receipt shape `check_validation_ledger`
  already relies on; `scripts/validate_receipt.py` (hand-rolled
  schema-subset validator, no `jsonschema` dep) cross-checks version +
  windows_label vs the `<version>__<label>.json` filename so the two
  can never disagree silently. JSON companions added for
  `1.5.0__release-evidence.json` and `1.5.0__kali_pty.json`.
- **WS-CASCADE-REHEARSAL** — `scripts/cascade_rehearsal.sh` runs
  `cargo publish --dry-run --allow-dirty --no-verify` for every
  publishable crate in DAG order and reports pass/fail per crate.
  Exit-code contract distinguishes green (0), expected fail-closed
  (2 — `[patch.crates-io]` present so a real cascade can't proceed
  yet), and unknown failure (1). Wired into CI as an informational
  `continue-on-error` job.

### Deferred out of 1.5.0

- **WS-ADVISORY-CLEANUP** (`RUSTSEC-2023-0071`, rsa 0.9 Marvin
  sidechannel) — scope is deeper than the plan estimated. The `rsa`
  crate is actively used across `crates/kerberos/src/csr.rs` (CSR
  generation), `crates/kerberos/src/pkinit.rs` (PKINIT sign/decode),
  and `cli/src/attacks/icpr_esc1.rs` (RSA key generation), AND reaches
  the tree transitively via the external `ms-icpr 0.1.2` sibling.
  Full removal is a crypto-migration workstream that needs its own
  version contract per `AI_RELEASE_GOVERNANCE.md` §3 — 1.5.1
  candidate. The advisory ignore in `.cargo/audit.toml` and
  `deny.toml` remains with its dated rationale.
- **WS-DEPS-MAJORS** (picky-krb 0.9 → 0.12) — prior 2026-09-01 attempt
  was reverted; ~30+ mechanical edits owed with an underlying failure
  mode to understand first. Own workstream. 1.5.1 candidate.
- **WS-FUZZ-DEEP** — definition of done is 7 consecutive nights green.
  Cannot compress into a session; runs continuously post-tag.
- **WS-LDAPS-CB-INVESTIGATE** — needs live packet capture against
  2019 / 2022 / 2025 DCs; lab unreachable at receipt-write; will spawn
  a follow-up implementation ticket only if it finds evidence.
- **WS-CLI-SHRINK** — 5 deferred callsite items; ~500 LOC refactor;
  own reviewed batch, not tacked onto the release.

## [1.4.10] — 2026-09-02

Hardening patch on top of 1.4.9 — bug-fix / defence-in-depth only, no
new operator-observable capability. The 1.5.0 branch (`docs/PLAN_1.5.0.md`)
carries the black-box no-cred assessment capability push on top of this
tree; see `docs/PLAN_1.4.10.md` for the full 1.4.10 workstream plan.

### Post-release polish on `main` — 2026-09-03

- Migrated all six production ccache sinks and all six production private-key
  sinks to `write_secret_artifact`; certificates, CSRs, reports, and replay
  stubs remain ordinary non-secret outputs.
- Repaired the helper's no-clobber contract: an existing path is preserved and
  returns `AlreadyExists` instead of being deleted before `create_new`.
- Windows secret creation now supplies a protected owner/SYSTEM/Administrators
  DACL directly to `CreateFileW(CREATE_NEW)`, including long-path handling and
  regression tests for the ACL and paths beyond 260 characters.
- Secret keys are persisted before irreversible Shadow Credential writes and
  certificate-enrollment requests, preventing an existing output path from
  leaving an unusable remote credential or mismatched on-disk cert/key pair.
- CI now distinguishes registry-independent package inventory from the manual
  post-cascade crates.io resolution check, so a GitHub-only tag is not marked
  red merely because same-version crates are intentionally unpublished.
- The release matrix now includes `x86_64-apple-darwin` on GitHub's Intel macOS
  runner. Distribution is fully aligned at 1.4.10: GitHub source + tag +
  release binaries, plus all 12 crates published to crates.io in the
  bottom-up cascade (core → secrets/ldap/graph/sysvol/kerberos/collector/
  bloodhound → checks → report → sdk → adhammer).

### Security

- **BF-1 — refuse authed plaintext LDAP-389 simple_bind.** New
  `crates/collector/src/lib.rs::require_bind_integrity` refuses to send
  an authenticated `simple_bind` over plaintext `ldap://` unless the
  operator sets the new `LdapConfig.allow_plaintext_bind = true`
  explicitly. Anonymous binds stay allowed (no credential in flight);
  GSSAPI over 389 stays allowed (SASL sealing on the wire); LDAPS stays
  allowed. Called from `Collector::connect` before the socket dials.
  1.4.9 AH-003 fixed the *write* path only; this closes the *read*
  path. 5 regression tests cover every branch.
- **BF-2 — GPP plaintext boundary.** `crates/sysvol/src/gpp.rs::
  decrypt_cpassword` now returns `SecretString` (was bare `String`).
  `GppHit.password` is `SecretString`. `finding()` no longer embeds
  plaintext into `affected[]` or `evidence.value` — the report body is
  redacted. New `write_dump()` helper is the ONE authorized exposure
  site (`.expose_secret()` greppable — exactly one hit). Regression
  tests cover the boundary + the write-dump helper.
- **BF-7 — LDAP + SYSVOL resource budgets.** LDAP paged-search loop
  enforces `LDAP_MAX_ENTRIES_PER_SEARCH = 500_000`. SYSVOL walk
  enforces `SYSVOL_MAX_WALK_DEPTH = 32`, `SYSVOL_MAX_FILE_BYTES = 4
  MiB`, `SYSVOL_MAX_HITS = 10_000`. Refusals log at `warn`; never
  silent short-return.
- **BF-8 — output control-char sanitization.** New
  `adhammer_core::sanitize::sanitize_terminal_output` strips C0 (except
  `\n\t`), DEL, Unicode C1, CSI, OSC (BEL- or ST-terminated, byte-
  capped) and 2-byte ESC escapes. Wired at `Report::build` — every
  `Finding` (title/detail/impact/remediation/affected/evidence) and
  every `AttackPath` (principal/target/step endpoints/step commands)
  passes through before the JSON / HTML / Markdown / text renderers
  read them. `WireExchange` intentionally not sanitized (wire dumps
  must stay byte-exact for reproducibility). 15 unit tests + one
  cross-renderer regression test.

### Added

- **Foundation types** (patch-safe additive; observable capability
  lands in 1.5.0). `crates/core/src/scope.rs` — `EngagementScope`,
  `ScopeTarget`, `CheckId`, `CheckClass`, `FindingStatus`,
  `Capability`, `CapabilityKind`, `NextAction`, `SecretHandle`,
  `ScopeError`. `crates/sdk/src/blackbox.rs` — `BlackBoxRunner`,
  `RunPolicy`, `ConsentPolicy`, `CheckSelection`, `RunSummary`,
  `RunnerRefusal`.
- **BF-3 — cross-cutting excludes.** `EngagementScope::allows(ip,
  hostname)` treats excludes as cross-cutting across identity forms:
  an exclude on either the hostname or the IP blocks the target when
  the caller supplies both.
- **BF-4 — runner budgets.** `BlackBoxRunner::start_host(ip)` enforces
  `max_hosts` (first-touch counted, repeat touches free);
  `may_run` enforces `max_duration_secs`. `RunnerRefusal` is a distinct
  enum so reports can render "why not."
- **BF-5 — PostCred capability gate.** `may_run(check, PostCred)`
  returns `RunnerRefusal::PostCredRequiresCapability` unless at least
  one capability has landed via `record_capability`.
- **`adhammer_core::secret_write::write_secret_artifact`** — no-clobber
  create-file helper for secret artifacts. Unix: `OpenOptions::
  create_new + mode(0o600)`. Windows: `CreateFileW(CREATE_NEW)` with
  a protected owner/SYSTEM/Administrators DACL. `SecretArtifact` enum
  names the artifact class for error messages.
- **`compile_error!` boundary guard at `crates/collector/src/lib.rs`**
  for the `tls-native ⊕ tls-rustls` mutex. `--all-features` was never
  supportable on this workspace (ldap3 upstream guards the same
  mutex); the ship-gate references the existing "check supported
  feature variants" job instead.
- **Live-DC integration tests** landed under `cli/tests/live_safe.rs`,
  `cli/tests/live_impact.rs`, `cli/tests/common/`. All `#[ignore]`d
  and env-var-gated (`ADH_DC`, `ADH_IMPACT=1`). `cargo test` stays
  hermetic offline.
- **Fuzz targets** for the new defence surfaces:
  `fuzz_targets/sanitize_terminal.rs` (byte-level sanitizer) +
  `fuzz_targets/scope_hostname.rs` (scope JSON deserialize +
  hostname normalize).

### Fixed

- `cargo fmt --all --check` — closes CI-FAIL-2 by landing
  `cli/tests/live_safe.rs` under formatted state.
- **`scripts/scrub_receipt.py` — UTF-8 stdout + context-aware DES-key
  scrub.** WS-RECEIPT-UTF8 forces `sys.stdout/stderr.reconfigure(utf-8)`
  so non-ASCII glyphs (✗ ✓ box-drawing) in adhammer output no longer
  crash the scrubber on Windows (default cp1252). WS-RECEIPT-DES adds
  a context-aware pattern for `krbtgt:<alg>:<hex>` short-hex values
  that the length-≥32 rule missed (des-cbc-md5 keys are 16 hex chars).

### Live-DC receipts

- `docs/receipts/1.4.10__{2019,2022,2025}.md` — cross-version live-
  validation against `testlab.local` DCs (Windows Server 2019, 2022,
  2025). Every receipt scrubber-approved (0 leak-terms matches).
  Behavioral fingerprint confirms OS mapping: Server 2025's krbtgt no
  longer emits DES keys (deprecated in default config), 2019/2022 do.
  Passing verb set consistent across all 3 (enum_krb_users,
  attack_dcsync_krbtgt, attack_secretsdump) — LDAPS-bind verbs
  (scan / enum adcs / attack roast) fail uniformly, matching the
  documented WS-LDAPS-CB-INVESTIGATE hypothesis (channel-binding
  hardening across the 2019+ line).

### Deferred to 1.5.1 (tracked in `docs/PLAN_1.4.10.md`)

- WS-CLI-GPP-DUMP-FLAG: expose `--gpp-dump-out <path>` in
  `attack scan` to reach `write_dump`.
- WS-LDAP-INTEGRITY-RESPONSE-BYTES: byte-level cap on paged responses.
- WS-LDAP-INTEGRITY-FAKE-SERVER: hermetic fake LDAP server test.
- WS-CLI-PLAINTEXT-LDAP-FLAG: expose `allow_plaintext_bind` per verb.

### Bug carry from 1.4.9

- **BUG-19** — `pac_credential_info` fuzz-found panic (picky-krb
  0.9.6 `generic-array` in AES-CTS-HMAC-SHA1 decrypt). Production-
  mitigated via `catch_unwind` around `decrypt_ticket_pac`; fuzz
  build (`-C panic=abort`) cannot catch the panic, so fuzz stays red
  until picky-krb 0.12+ lands (1.5.0 `WS-DEPS-MAJORS`).
- **CI-1 closed on `main`** — every CI run performs registry-independent
  `cargo package --list` inventory for all 12 crates. Full registry resolution
  is an explicit manual post-cascade check because unpublished same-version
  workspace dependencies cannot resolve from crates.io before that cascade.

## [1.4.9] — 2026-09-01

### Security — SEC-1 protocol-library remediation (2026-09-01)

Closes every High and Medium finding from the 1.4.9 protocol/library
security review (`docs/AH-review 2026-09-01`, canonical revision
`9752c8f`). Every fix carries a same-cycle regression path.

- **AH-001 / AH-002 — LDAP BER hardening.** `crates/ldap/src/lib.rs`
  now rejects indefinite lengths, non-canonical long-form lengths and
  length octets beyond `MAX_BER_LENGTH_OCTETS = 4`; every arithmetic
  step uses `checked_add` / `checked_mul`; `read_tlv_in(buf, pos,
  parent_end)` bounds child TLVs to the enclosing container; a
  16 MiB `MAX_LDAP_MESSAGE_BYTES` cap and 15 s connect / 30 s I/O
  deadlines wrap every request. A hostile or misdirected LDAP peer can
  no longer drive unbounded allocation or an indefinite blocking read.
- **AH-003 — plaintext LDAP-389 write refusal.** `bind_ntlm` on the
  minimal `LdapClient` now errors out instead of accepting a password;
  post-bind SASL integrity is not implemented, so `--ldap389` write
  paths (`attack abuse --action add-keycred` in direct-auth mode) are
  refused pending verified LDAPS or a negotiated SASL layer. The
  relay bind (`sasl_step1` / `sasl_step2`) is deliberately preserved.
- **AH-004 / AH-005 — WinRM byte budgets and checked chunk framing.**
  `cli/src/winrm.rs` adds `MAX_WINRM_HEADER_BYTES = 64 KiB`,
  `MAX_WINRM_BODY_BYTES = 16 MiB`, `MAX_WINRM_CHUNK_LINE_BYTES = 1 KiB`,
  `MAX_WINRM_CHUNKS = 8192`, `MAX_WINRM_OUTPUT_BYTES = 64 MiB` and a
  60 s `WINRM_HTTP_READ_TIMEOUT` around every header + body read.
  Signature and chunk-size arithmetic use `checked_add`; ambiguous
  framing (chunked + `Content-Length`) is refused.
- **AH-006 — zeroizing `SecretString` end-to-end.** `crates/core/src/
  redact.rs` adds `SecretString` and `SecretBytes` newtypes with
  `ZeroizeOnDrop` plus redacted `Debug` / `Display`. `SmbAuth`,
  `LdapAuth`, `OptAuth`, `winrm::Secret::Password`, `shadowcred::
  pfx_password`, `guided::GuidedArgs.password` and the three
  `dialoguer::Password` prompt sites in `interactive.rs` now carry
  `SecretString`. `SecretString::FromStr` accepts `env:VAR`,
  `@file:PATH` or literal (deprecated) at ingress. `guided.rs`
  emits the argv `--password` value as the literal string
  `env:ADHAMMER_GUIDED_PASSWORD` and sets the env var on the child
  `Command` before `spawn` — the password literal never appears in
  child argv, so `ps` / `procmon` / `Win32_Process` cannot recover it.
- **AH-007 — write-DACL boundary validation.** `cli/src/attacks/
  abuse.rs` gains `validate_acl_bytes(&[u8])` which rejects
  `AclSize < 8`, requires the declared size to match the slice
  length, enforces `AceSize >= 4`, and walks every ACE with
  `checked_add`. `prepend_generic_all_ace` refuses malformed DACLs
  instead of panicking on out-of-range slice indices.
- **WS-001 / WS-002 — `windows-sddl` ACL bounds and NULL DACL state.**
  Sibling `windows-sddl 0.1.3` (commit `bb57722`) validates `AclSize`,
  requires `AceSize >= 8`, sanity-checks `AceCount`, models an
  explicit `DaclKind::{NotPresent, Null, Present}` and refuses
  descriptors whose DACL offset disagrees with `SE_DACL_PRESENT`.
  Cargo `[patch.crates-io]` points every workspace + transitive user
  at the local checkout until the release publishes.

### Live-validation receipts — 3 of 3 Windows versions

Full release matrix landed. Every receipt approved.

- `docs/receipts/1.4.9__2025.md` — DC01, Server 2025.
- `docs/receipts/1.4.9__2022.md` — Server 2022.
- `docs/receipts/1.4.9__2019.md` — Server 2019.

**Consistent result across all three DCs:** the SMB / Kerberos verbs
pass (`enum_krb_users`, `attack_dcsync_krbtgt`, `attack_secretsdump`),
LDAP-dependent verbs (`scan`, `enum_adcs`, `attack_roast`) return the
same `AcceptSecurityContext error, data 52e` — Microsoft's default
LDAPS channel-binding hardening now rejects the NTLM SASL bind path
across the whole Server 2019 / 2022 / 2025 matrix, regardless of the
bind-identity form (`DOMAIN\user`, `user@REALM`, DN, sAMAccountName).
The SMB / Kerberos code path uses the exact same credentials
successfully, so this is a DC-hardening surface, not a credential
issue. The 1.5.0 workstream `WS-LDAPS-CB` addresses it end-to-end by
implementing LDAPS channel-binding tokens; until then, the SMB path
is the supported route for authenticated AD queries on any patched
Server.

Behaviour on the failing verbs is graceful-fail with a specific error
message + non-zero exit — the exact class of hardening the SEC-1
batch guarantees. No panics, no unbounded reads, no leaked secrets in
the failure paths (verified by the scrubber + pre-commit leak-hook on
every receipt).

### Fixed

- Install the AWS-LC Rustls provider at CLI startup so LDAP and AD CS TLS builders cannot panic
  when the MSSQL client also activates Rustls's `ring` feature.
- Remove the unused, unmaintained `rustls-pemfile` dependency and its advisory exceptions.
- Remove `ms-tds` and unvalidated `ms-gkdi` from the default dependency graph. MSSQL is now an
  explicit `mssql` feature; the collector adapter is available only through its owner crate's
  `experimental-gkdi` feature.
- Propagate the workspace MSRV to every published `adhammer-*` package and CI-check the supported
  default, native-TLS, and optional-capability feature combinations.
- Make `--no-default-features` a valid plain-LDAP build; LDAPS attempts fail before dialing with a
  clear instruction to select one of the mutually exclusive TLS backends.
- Resolve `env:VAR` credential references in the shared CLI boundary and fail closed when the
  reference is malformed or missing.
- Harden live-validation receipts: reject literal passwords and unsafe Windows labels, share one
  canonical leak-pattern list with the pre-commit hook, sanitize target-controlled output without
  putting the secret on a subprocess command line, and publish receipts only after JSON validation.

## [1.4.8] — 2026-08-30

**Capability-expansion release** — closes the "broad passive assessor → operational
offensive tool" gap. Original 20-vector plan lands **18 of 19 vectors LIVE**
(WS-SKELETON-KEY permanently dropped from plan; WS-DPAPI-MASTER-KEY moved deferred
→ LIVE after upstream dpapi-offline 0.1.1 landed the MS-DPAPI PBKDF2 fix), 1 deferred
to 1.4.9 with explicit rationale ([`docs/PLAN_1.4.8.md`](docs/PLAN_1.4.8.md)).
One sibling crate published as the WS-DPAPI-MASTER-KEY enabler (`dpapi-offline
0.1.1`, byte-oracle-validated on Server 2025); ADhammer itself and every other
sibling crate stay local this cycle.

### Added — Phase A: net-new implementations

- **WS-KERBRUTE** (`enum krb-users`) — Kerberos user enumeration via
  pre-auth-less AS-REQ. No LDAP creds needed; leaks user existence via KDC
  error codes (RFC 4120 §7.5.9: `PRINCIPAL_UNKNOWN` vs `PREAUTH_REQUIRED`).
  Also surfaces AS-REP-roastable accounts (`DONT_REQ_PREAUTH` flag) with a
  copy-pasteable `attack roast` command.
- **WS-DIAMOND-TICKET** (`attack diamond`) — variant of Golden that inherits
  real KDC-issued timestamps + cname from a legitimate TGT; only PAC
  groups/SIDs are attacker-chosen. Removes the anomalous 10-year-validity
  IOC that fingerprints Golden.
- **WS-SID-HISTORY-INJECT** (`attack golden --sid-history <SID>`) — canonical
  cross-forest SIDHistory injection; `golden.rs` docstring rewritten to name
  the vector with a paste-ready example.
- **WS-ESC1-EXPLOIT** (`attack esc1`) — 6-stage `StageChecklist`-wrapped ESC1
  exploit with explicit KB5014754 handling.
- **WS-ESC3-CHAIN** (`attack icpr-esc1` variants) — per-variant checklist
  builder + doc-name for the ESC3 Enrollment Agent chain.
- **WS-UNPAC-PKINIT** (`attack unpac`) — PKINIT with a cert, extract NT hash of
  the impersonated principal from the AS-REP's `PAC_CREDENTIAL_INFO` padata
  (MS-PAC §2.6); chains into pass-the-hash. New module
  `crates/kerberos/src/unpac.rs` (~320 LOC) with two unit tests + KEY_USAGE
  constant KERB_NON_KERB_SALT (16).
- **WS-DPAPI-MASTER-KEY** (`attack dpapi-master-key`) — offline classic-DPAPI
  masterkey decryption. Given a masterkey file from `%APPDATA%\Microsoft\
  Protect\<SID>\<GUID>` and either a password or pre-derived 20-byte pwdkey,
  returns the 64-byte AES256 master key that unlocks every `CryptProtectData`
  blob owned by that SID (Chrome cookies, Wi-Fi / RDP / VPN creds,
  Credentials vault, Outlook profiles). New module
  `cli/src/attacks/dpapi_mk.rs` (~150 LOC) with a 5-stage `StageChecklist`.
  Sibling crate `dpapi-offline` bumped 0.1.0 → 0.1.1 as the enabler (see
  Deps note below); ADhammer's verb wraps `dpapi_offline::unlock_masterkey`
  which tries standalone SHA1 → domain MD4 → Protected-Users
  PBKDF2-SHA256 automatically. Live-validated end-to-end on 2026-08-30
  against a Server 2025 domain Administrator masterkey (<dc-ip> /
  DC01 testlab): output matches impacket 0.14 `dpapi.py masterkey` byte-
  for-byte across all three pre-key paths.

### Added — Phase B/C/D/F: already-implemented primitives doc-named to plan

- **WS-PSEXEC / WS-ATEXEC / WS-WMIEXEC** (`attack exec` / `atexec` / `wmiexec`) —
  three lateral RCE channels (SVCCTL / MS-TSCH / DCOM `Win32_Process.Create`)
  with distinct host telemetry footprints. **WS-WMIEXEC moved from
  `[SEALED-BLOCKED]` (Phase F) to LIVE (Phase B)**: existing
  `dcerpc::dcom_wmi::wmi_exec` works without the cut WS-4-P2 sealed path;
  DCOM ACTIVATION completes and `Win32_Process.Create` output is poll-read
  over C$.
- **WS-EVIL-WINRM** (`attack winrm`) — WS-Man over 5985 with NTLM + MS-NLMP
  message encryption; pass-the-hash via `--nt-hash`.
- **WS-DELEGATION-CAPTURE (PARTIAL)** (`attack unconstrained`) — LDAP-only
  recon of `TRUSTED_FOR_DELEGATION` hosts ships; the AP-REQ-parse
  capture listener is documented as follow-up work in the module header.
- **WS-SAM-SECURITY-DUMP** (`attack secretsdump`) — MS-RRP fast path
  (bootkey via class-name walk, no 15 MB hive downloads) + `reg save`
  fallback + SYSKEY offline decrypt through `adhammer_secrets`.
- **WS-NTLMRELAYX-SMB-LDAP** (`attack relay`) —
  `smb2_client::server::RelayConn::listen` + LDAP (Shadow Credentials /
  RBCD) / AD CS Web Enrollment (ESC8) / MS-ICPR (ESC11) forwarders.
- **WS-COERCE-SENDER** (`attack coerce`) — MS-RPRN / MS-EFSR / MS-DFSNM /
  MS-FSRVP senders; docstring points at WS-NTLMRELAYX as the paired
  listener for the full "coerce + capture" chain.
- **WS-LLMNR-POISON** (`attack poison`) — LLMNR (UDP 5355) + NBT-NS
  (UDP 137) lure that pairs with WS-NTLMRELAYX for the capture end.
- **WS-ESC8-END-TO-END** (`attack adcs-relay`) — dedicated NTLM-over-HTTP
  relay to AD CS Web Enrollment.
- **WS-DCSHADOW-DRSR** (`attack dcshadow`) — WS-2 DRSUAPI push path (works
  on Server 2019/2022/2025); LDAP path stays as fallback for ≤ 2016 but is
  live-verified dead on 2019+ (see [[dcshadow-ldap-dead-on-2019plus]]).

### Deferred to 1.4.9 (1 of 19)

- **WS-NTDS-OFFLINE.** Sibling `ese-parser` at v0.1 scope (668-byte header
  + random-access page read). B-tree walk / catalog decode / row+tag decode
  are v0.2 roadmap; downstream `ntds-parse` crate not published. Live
  DCSync already covers the same NT-hash + krbtgt + trust-key output.
  Slated as the 1.4.9 headline feature once ese-parser v0.2 lands.

### Dropped from plan

- **WS-SKELETON-KEY** — permanently cut, not deferred. LSA memory patch
  of lsass.exe on the DC has no unique operator value: WS-GOLDEN-TICKET
  already provides "log in as any user after DA" persistence with a
  better AV/EDR surface, and skeleton-key needs a per-Windows-version
  binary shim. Building it because it's on the list would be sunk-cost.
  Plan denominator drops 20 → 19.

### Fixed

- Three clippy regressions in `adhammer-kerberos` after the Phase A ship
  (unused `Cipher` re-export in `unpac.rs`, doc_lazy_continuation in
  `pac.rs`, `too_many_arguments` on `forge_ticket_with_timestamps` with
  explicit `#[allow]` + rationale).
- Mid-release commit chained `cargo clippy … | tail -3` and masked the
  strict-warning exit code (786e133); restored to unpiped in
  60ca37f with a note in the commit message.

### Removed

- **`check krb-seal` subcommand + `AesCts96Sealer` + rpc_seal RFC 3961/3962
  primitives.** WS-4-P2's live-DC probe of the AES256-CTS-HMAC-SHA1-96 sealer
  reached BIND_ACK byte-correct against Server 2025 but every wrap-token
  layout permutation tried (in 1.4.7 and again in 1.4.8) tripped the
  identical `SMB2 status 0xC00000AE (STATUS_PIPE_BUSY)` on the first opnum.
  Blind hypothesis-search on a binary DC response converges to nothing;
  closure requires a Windows-native → DC Wireshark capture over
  `\PIPE\lsarpc` under Kerberos-sealed to byte-diff against our output.
  Rather than ship the `[SCAFFOLDING]` label indefinitely, the code is cut.
  Git history preserves everything at tag `v1.4.7` and earlier for the day
  the capture lands. Deleted files: `cli/src/checks/krb_seal.rs`,
  `crates/kerberos/src/rpc_sealer.rs`, `crates/kerberos/src/rpc_seal.rs`.
  Also drops `aes = "0.8"` + `dcerpc` deps from `adhammer-kerberos`
  (the sealer was their only consumer). `check adcs` remains.

### Notes

- **Deps.** No new third-party deps this release. Sibling icedracon crates
  covered every wire path. **`dpapi-offline` bumped 0.1.0 → 0.1.1** (the
  WS-DPAPI-MASTER-KEY enabler, byte-oracle-validated on Server 2025 vs
  impacket 0.14).
- **Determinism.** Byte-identical scan output across Windows and Kali given
  the same DC state — unchanged from 1.4.7.
- **Coverage counting.** 73 unique attack surfaces total (58 pre-recon
  checks + 15 pre-existing attack verbs + 19-item capability plan − 4
  overlap between plan and pre-existing + 1 dropped SKELETON-KEY). Plan-
  vs-shipped table in `docs/PLAN_1.4.8.md`.

## [1.4.7] — 2026-08-29

The **"security-audit remediation + assurance-lane polish"** release. Every one of
the eight findings from the pre-ship tag-vs-main audit (2 P1, 5 P2, one stale
version) is closed and PTY-verified on Kali VBox against DC01 Server 2025 before
tag. Report gains two new coverage panels + a deterministic content hash for
audit-trail; interactive UX gains guardrails against silent password exposure.

### Security fixes (P1)

- **P1-A — hidden secret entry.** Four sites in the interactive wizard used
  `Input::new().interact_text()`, echoing keystrokes to the terminal (scrollback,
  tmux history, SSH logs): NT hash, `set-password` value, constrained-delegation
  password, AES256 key. Now use `Password::new().interact()` — dialoguer's hidden
  entry (`[hidden]` marker). Same primitive already backed the regular Password
  path; consolidated for parity. Live-verified in a Kali PTY: a 32-hex hash fed
  to the prompt never appears in the recorded stream.
- **P1-B — plaintext-LDAP downgrade requires explicit consent.** Prior behavior:
  if LDAPS:636 was unreachable, the wizard silently stored `ldap://<dc>:389`
  and the collector did a simple bind — sending the user's password OVER THE
  NETWORK IN THE CLEAR without any acknowledgement. Now: any downgrade prompts
  with hard security wording ("password sent unencrypted", "local listener can
  capture it"), defaults to No, and refuses to proceed unless the user
  explicitly says yes. Refusal errors with a specific fix hint (install ADCS
  or point `--url` at an LDAPS-capable DC).

### Quality fixes (P2)

- **P2-A — hex-alphabet validation on NT hash + AES256 key.** Prior length-only
  check accepted `32 * "Z"` as an "NT hash", producing a cryptic downstream bind
  failure. Now `validate_with` enforces `is_ascii_hexdigit` on every char.
- **P2-B — `NO_COLOR` respect on Spinner.** `Spinner::start` gated animation on
  `is_terminal()` only; `NO_COLOR=1` still got ANSI colors + cursor motion. Now
  falls through to the plain non-TTY start-line path when `no_color()` is true
  (consistent with every other color surface in `ui.rs`).
- **P2-C — deduped failure display.** `run_action_with_brief` renders a full
  failure card (checklist + outcome + reason + diagnosis + hint); the outer
  callers then also `ui::bad(e)`'d, painting one connection-refused as a wall
  of red across three renders. Inner render is now authoritative.
- **P2-D — strict clippy exit 0.** Three `needless_borrow` errors in the
  WS-CTRLMAP CI-gate tests (`describe(&id)` where `id: &'static str`) surfaced
  only under `--all-features`. Fixed to `describe(id)`.
- **P2-E — honest `-v/-vv/-vvv` docs + conditional banner tip.** Prior help text
  promised "wire-layer detail from dcerpc/smb2-client/ntlmssp" but a
  workspace-wide macro census shows **0 trace!, 2 debug!, 6 info!, 7 warn!** —
  the wire crates carry ~zero tracing today, so `-vvv` ≈ `-v` output. Rewrote
  help to describe actual current behavior + explicitly flagged wire-layer
  per-PDU tracing as a **1.4.8 track**. The CLI plumbing stays wired so the
  firehose lights up once the calls land. Banner tip in the interactive header
  no longer says "wire trace on" (lie) and only renders when `--quiet-interactive`
  is NOT set (the tip previously printed even in the state that opted out).

### New workstreams

- **WS-INT-VVV** — bare `adhammer` invocation with no subcommand auto-forces
  `-vvv` verbosity in a real TTY. `--quiet-interactive` opts out. See WS-KRB-TRACE
  for the tracing calls the auto-force now activates.
- **WS-KRB-TRACE** — `adhammer-kerberos` hot paths instrumented with
  `tracing::debug!` / `tracing::trace!` / `tracing::warn!`: `get_tgt` +
  `asktgt` (AS-REQ round-trip narration + byte counts + KDC error codes),
  `get_service_ticket` (TGS-REQ round-trip), sealer `seal_pdu` +
  `unseal_pdu` (WRAP-token assembly / verify with role + stub-len + seq).
  Redaction discipline audited: only identifier strings + byte lengths +
  sequence numbers + etypes emitted; never key bytes, ticket contents, or
  hashes. Turns `-vv` and `-vvv` from placebo (P2-E) into meaningful
  Kerberos wire narration on the crate we own. Wire-layer per-PDU tracing
  inside dcerpc/smb2-client/ntlmssp themselves stays 1.4.8-track (needs
  upstream pub cycles). **Windows note**: Git Bash / MSYS2 pipes silently
  swallow tracing_subscriber's stderr writes; run under cmd.exe /
  PowerShell / any Linux terminal to see the output (heads-up added to the
  `-v/-vv/-vvv` help doc).
- **WS-REDACT-TICKET** — `Tgt` and `ServiceTicket` grow manual `Debug` impls
  that redact `session_key`, `principal_key`, and every ticket + authenticator
  byte behind `<redacted N bytes>`; the `authtime`, `endtime`, `nonce`, `flags`,
  `sname` fields still print for debugging. Prior `#[derive(Debug)]` leaked
  session keys under `--debug`. Round-tripped through the test corpus.
- **WS-DEFENDER-DOC** — README gains a Windows install workaround for Defender
  quarantining `cargo build --release` outputs (add exclusion for the target
  directory + one-line PowerShell). Deals with the fresh-Windows-user first-hit
  frustration surfaced in 1.4.6 QA.
- **WS-OUT-ALL-STAGES** — `scan --out-all <dir>` now emits a proper
  StageChecklist entry (`✓ all-formats · <total_bytes> bytes`) covering all four
  written files instead of only counting the last format written.
- **WS-CTRLMAP** — in-house AD-pentest control-area + kill-chain taxonomy. Every
  one of the 60 registered check IDs carries ≥1 `ADP-NN` code (`ADP-01`..`ADP-30`
  fully documented in `docs/CONTROL_AREAS.md`) and one of six kill-chain phases
  (enumeration → initial-access → priv-esc → lateral-movement → persistence →
  domain-dominance). Report HTML gains two new panels ("Control-area coverage"
  + "Kill-chain coverage" in canonical lifecycle order). CI gate: any new check
  missing a code or phase fails `cargo test`. No third-party cert-body or
  methodology labels — neutral in-house identifiers so downstream consumers can
  cross-map to whatever framework they prefer.
- **WS-CLEAN-REPORT** — 0-findings "hardened bill of health" UX. Green
  assurance banner renders only when `findings.is_empty()`, sourced from the
  WS-CTRLMAP roll-ups ("N checks across K control areas and M kill-chain
  phases, no condition tripped") with a preconditions-not-met subtext for
  checks that couldn't fully exercise their target. **Report fingerprint
  footer** (always rendered): sha256 of the canonical JSON serialization +
  domain label — enables archive-by-hash, tamper spot-check, and baseline-diff.
  Determinism live-verified: byte-identical across back-to-back same-env runs
  including the embedded hash.
- **WS-4-P2 partial** — Filler-byte MIC zero + fault-mnemonic correction in the
  Kerberos RPC sealer. Documentation/code alignment fix (doc comment said
  "Filler, EC, RRC" but only EC + RRC were zeroed); does NOT close the sealed
  REQUEST fault (which is STATUS_PIPE_BUSY = 0xC00000AE, NOT PIPE_BROKEN as
  prior notes claimed). `check krb-seal` stays `[SCAFFOLDING]` + `hide_from_help`
  until the Windows-native Wireshark reference capture unblocks it (1.4.8).

### Dependencies

- **windows-sddl** bumped `0.1.1 → 0.1.2` to track the icedracon 2026-08-29
  windows-* wave (win32-min 0.1.3, windows-token / windows-scm / windows-lsa /
  windows-eventlog-native all 0.2.1, windows-sddl 0.1.2). Additive-only patch
  on that side; ADhammer picks up the latest fixes without semver churn.

### Gate

- `cargo fmt --all` clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` exit 0.
- `cargo test --workspace`: 266 passing (+17 from 1.4.6's 249).
- Live-DC scan: 29 findings / 58 checks / all three 1.4.7 report panels rendered;
  both Windows + Kali builds; back-to-back same-env determinism holds.
- PTY on Kali: hidden password entry confirmed; plaintext-LDAP consent + refusal
  path work as scripted.

## [1.4.6] — 2026-08-27

The **"proof on every line, graph on every report"** release. Every finding a scan
produces now carries three layers of proof — the interpreted evidence (WS-PROOF),
the ground-truth artifact, and the wire-level exchange that produced it — and any
new check that skips them fails CI (WS-PROOF-70 + WS-WPT strict gates). The HTML
report grows a full BloodHound-style principal graph with pan/zoom/click alongside
the existing attack-paths view. The interactive attack surface (six subcommands)
gets rich per-stage checklists that name the exact failing pipeline step.

- **WS-THEME** — HTML report ships with a light/dark toggle; both themes are legible
  (WCAG AA) and every element (SVG graph, coverage matrix, chips) themes via CSS
  tokens.
- **WS-PROOF-70** (three parts) — every one of the 58 registry checks carries a
  non-empty `evidence` and `impact` field; the CLI text summary emits `impact:` and
  `proof:` lines under every top finding; the coverage matrix row for a tripped check
  shows a `✓ proof` chip. Enforced by a CI gate test that walks `registry()` against
  a kitchen-sink fixture — a new check without evidence + impact fails `cargo test`.
- **WS-WPT — wire-proof transcripts on every finding** — every `Finding` gains an
  `exchange: Vec<WireExchange>` field (additive, `serde(skip_serializing_if =
  "Vec::is_empty")`). The LDAP collector records every search it runs and links each
  DN to the search that captured it; `run_all` auto-attaches the synthesized
  (Sent search + Recv count) exchange to every LDAP-passive finding — 50 of 58
  checks get wire proof without any per-check code change. Active probes (ESC8 HTTP,
  ESC-registry MS-RRP, SYSVOL SMB) record their own bespoke `Sent`/`Recv` frames at
  the probe site. Rendered as an expandable `<details>` block in HTML, collapsible
  section in MD, one-line `wire:` in txt, full array in JSON. Strict CI gate with
  an **empty legacy allowlist** — any future finding without wire proof fails the
  build.
- **WS-BHG — BloodHound-style principal graph** — new `<h2>Principal graph</h2>`
  panel below the WS-R1 attack-paths view. Tier-0 nodes on a horizontal centerline,
  neighbors on concentric rings (pruned to ≤250 nodes for legibility). Deterministic
  layout via a 32-slice integer cosine LUT so two scans of the same domain produce
  byte-identical SVG. Inline (~1 KB) vanilla-JS interaction layer: pan on mouse drag,
  zoom about cursor on wheel (clamped 0.4× – 4×), click a node to highlight neighbors
  and dim the rest, Escape clears. Self-contained — no d3, no CDN. Static SVG stays
  fully legible with JS off.
- **Rich stage checklists for six more attack subcommands** — `asktgt`, `gmsa`,
  `silver`, `golden`, `laps`, `ptt` (pass-the-ticket) now show per-stage progress
  and land `mark_current_failed` on the exact failing step. Same pattern already
  shipped for `spray`, `dcsync`, `roast`. The operator sees where the pipeline
  stopped instead of one opaque "execute action" line.
- **`Redacted<T>` secret-hiding newtype + `--verbose` / `--debug` tracing filters** —
  session credentials wrapped so `{:?}` prints `***`; verbose tracing surfaces every
  major step and debug adds wire-layer detail from `dcerpc`/`smb2-client`/`ntlmssp`
  without leaking `Redacted`-wrapped secrets to the debug stream.
- **End-of-run stage checklist card** — `scan`, `auto`, and interactive-mode
  operations render the same StageChecklist shape at exit.
- **LDAP first-touch UX** — step-by-step connect diagnostic with expanded error
  causes (TLS/cert, channel binding, reachability) so the first bind failure names
  the actual root cause instead of a generic hint.
- **WS-4-P2 sealed Kerberos RPC bind — primitives + BIND verified** — RFC 3961/3962
  crypto primitives, HMAC + subkey derivation, `AesCts96Sealer` implementation of
  `dcerpc::KrbSealer`. The BIND path is byte-correct against Windows Server 2025
  (BIND_ACK live-verified against DC01). The sealed REQUEST WRAP-token layout is
  not yet finalized — the `check krb-seal` diagnostic subcommand is **hidden from
  `--help`** and marked `[SCAFFOLDING]`. Closure lands in 1.4.7 once a Windows-client
  → DC Wireshark capture is available. Downstream `ms-dcom` / `ms-wmi` fills are
  gated on the same closure.

Full changelog: **[CHANGELOG.md](CHANGELOG.md)** · release archive:
**[GitHub Releases](https://github.com/icedracon/adhammer/releases)**.

## [1.4.5] — 2026-08-26

The **"three new libs on crates.io"** release — carried the interactive menu
polish forward and shipped three brand-new standalone icedracon protocol crates
alongside the workspace.

- **Interactive menu now surfaces `attack dns`, `enum sccm`, `enum scom`** — the
  1.4.4 verbs were CLI-only; the guided front door now dispatches to them cleanly.
- **`auto` / guided bundle carries the full 58-check coverage matrix** — the
  exported `auto-report.{json,md,html,txt}` now shows "checked X, N tripped,
  M clean" (matching what `scan` already had in 1.4.4); the JSON artifact carries a
  `coverage[]` array of 58 rows.
- **[`ms-scmr`](https://crates.io/crates/ms-scmr) 0.1.0** — MS-SCMR (Service
  Control Manager Remote) client foundation. Pure-Rust remote-service management
  from Linux.
- **[`ccache-io`](https://crates.io/crates/ccache-io) 0.1.0** — MIT-Kerberos
  `ccache` + Windows `.kirbi` codec. Every Rust Kerberos toolchain finally has a
  shared interop format.
- **[`ms-bkrp`](https://crates.io/crates/ms-bkrp) 0.1.1** — MS-BKRP (BackupKey
  Remote Protocol). DPAPI master-key recovery for DFIR + post-DA persistence audits.
- **LDAP-failure diagnostics** — a failed bind names the actual cause (TLS/cert,
  channel binding, reachability), so first-touch setup from Kali or PowerShell is
  faster to debug.

Live-validated end-to-end against Server 2022 and Server 2025 DCs.

## [1.4.4] — 2026-08-26

The **"read the whole picture"** release. Every scan now ships a visual
control-path graph and a complete coverage matrix inline in the report — every
check appears with its status and evidence, not just the ones that fired. Adds
the last two carryover items from 1.4.3's Tier-1 Phase-3: `attack dns` (ADIDNS
write) and `enum sccm` / `enum scom` (Configuration Manager / Operations Manager
discovery). Also folds in a first-touch UX fix for LDAP connection failures so
operators see the actual cause, not a generic "unreachable" hint.

**Deferred to 1.4.5:** WS-4-P2 Kerberos sealed RPC bind (multi-day crypto work,
lands as `dcerpc 0.2.8` additive), WS-1-P3 MSSQL live validation, WS-2-P3
DCShadow live push, WS-8-P2 real PFX export on `attack shadowcred`.

### Report headlines

- **In-report BloodHound-style control-path graph.** Every HTML report includes
  a deterministic, self-contained SVG (`crates/report/src/graph_svg.rs`) — no
  external CDN, no JS runtime — laid out longest-path-first, byte-stable across
  runs (no clock, no RNG). Zero plumbing changes: the report was already carrying
  the graph subgraph in `top_paths`.
- **Full 58-check coverage matrix rendered in every report.** `scan` now uses
  `run_all_with_coverage()` and the report exposes each check's `id`, whether it
  fired, and how many findings it produced — a machine reader can tell "check
  ran clean" from "check wasn't run". Complements WS-PROOF (1.4.3): fired
  findings carry ground-truth evidence, absent ones now carry the negative signal.
  Registry stays at 58 checks; 71 = distinct finding-ID literals (one check like
  `VulnerableCertTemplates` emits `A-Esc1..16`).

### New attacks / enum

- **`attack dns`** — ADIDNS write over LDAP: `add-a` / `modify-a` /
  `tombstone` / `delete`, `--dry-run` default-safe, records placed under
  `DomainDnsZones` or `--forest ForestDnsZones`. Composes the
  `adhammer_collector::dns_record::build_a_record` helper that landed in 1.4.2.
- **`enum sccm` / `enum scom`** — Configuration Manager / Operations Manager
  discovery over LDAP. Absent container = clean output ("not present"), not a
  failure. Adds `Collector::search_subtree(base, filter, attrs) -> Vec<AdObject>`
  as the reusable generic subtree helper.

### Fixed

- `adhammer` interactive mode now diagnoses the actual reason an LDAP bind
  fails (untrusted cert, wrong credentials, wrong URL, unreachable host) instead
  of printing a generic hint. First-touch operators on lab DCs with self-signed
  certificates get a clear next step, not `Connection reset by peer`.

### Engineering

- 194 workspace tests / 0 failing (was 185, +9 new).
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets
  -- -D warnings` clean on the ship commit.
- MSRV unchanged (1.87). No new external dependencies.

## [1.4.3] — 2026-08-25

The **"prove it, cover it"** release. Extends the `1.4.2` trust-surface cleanup
with ground-truth evidence on every finding, a wider passive-detection registry,
and baseline diffing — on top of the interactive UX overhaul.

> **Live-validated 2026-08-25** against both `testlab.local` forests (Server 2025
> DC01 + Server 2022). `scan` produced evidence-backed findings (16/16 carry
> ground-truth evidence on each DC), the WS-19 baseline diff detected real deltas,
> the ESC-registry probe folded into scan, and `dcsync krbtgt` matched the
> known-good hash on both DCs. Offline gate green (`cargo test --workspace`,
> `clippy -D`). Tier-1 Phase-3 completions (sealed-bind, MSSQL/DCShadow live,
> `attack dns`, PFX export) are deferred to 1.4.4.

### Added

- **Ground-truth evidence on every finding (WS-PROOF).** Each `Finding` now
  carries structured `Evidence` (source + raw value) — the actual LDAP
  attribute, registry key, or wire status that substantiates it — rendered in
  the JSON, HTML, Markdown, and terminal reports, so a reviewer can verify each
  finding by hand instead of trusting the verdict.
- **Passive check registry expanded 41 → 56 (WS-COVERAGE), all evidence-backed.**
  Notable new rules: constrained delegation targeting a domain controller
  (`P-ConstrainedToDc`, Critical); broad principal directly in a Tier-0 group
  (`P-BroadInTier0`, Critical); Key Admins / Enterprise Key Admins membership
  (`P-KeyAdmins`); foreign/cross-forest and computer accounts in Tier-0 groups
  (`P-ForeignInPriv`, `P-ComputerInPriv`); cleartext `userPassword` /
  `unixUserPassword` (`A-CleartextSecret`); weak RSA certificate-template key
  size (`A-WeakCertKeySize`, ECC-aware); weak fine-grained password policy
  (`A-WeakFgpp`); password-like strings in `description`/`info`
  (`A-PasswordInDescription`); privileged accounts missing from a populated
  Protected Users (`P-AdminNotProtected`); plus constrained delegation, broader
  Kerberoastable/delegatable-admin coverage, key-credential-on-admin, and
  expired-LAPS detections.
- **Baseline diff (WS-19).** `scan --baseline <prior.json>` tags findings
  `NEW` / `RESOLVED` / `SEVERITY-CHANGED` by `(rule id, affected object)`
  against a prior scan. The JSON report gains a `baseline_diff` object; the
  HTML / Markdown / text reports gain a diff section and per-finding tags.
- **Auto runs the DC posture probe (WS-AUTOSCAN)** — the read-only
  security-posture probe now fires automatically inside an `Auto` run.
- **Wider auto-validation (WS-AUTOVAL)** — the guided flow now captures real
  PoC proof for more finding classes (e.g. Kerberoastable service accounts).

### Changed

- **Narrated Auto / Guided flow** — connection summary, named phases with
  elapsed timing, clearer clean/finding states, inline proof snippets, export
  choices, and a final run summary card.
- **Shell-safe prompts** — numbered menus now print controls inline, password
  prompts degrade to visible entry when hidden input is unavailable, and the
  non-Windows session-save refusal became an explicit three-way choice instead
  of a dead-end warning.
- **Single-attack framing** — interactive attack runs now show a compact
  preflight card plus timed success/failure framing so the operator sees the
  action, proof expectation, and likely next step before and after execution.
- **Structured-output safety preserved** — the interactive narrator stays on
  the human path while machine-readable flows keep their existing clean-output
  contract.

## [1.4.2] — 2026-08-24

Public-slot replacement for the yanked `1.4.1` line. Carries the local `1.4.1`
workspace payload forward under the `1.4.2` version and tightens the release
truth surface before publish.

### Changed

- **JSON contract** — `--json` now emits JSON-only stdout for attack / enum /
  dump flows. Human/progress output is captured into the evidence field instead
  of breaking downstream parsers.
- **Graph executor templates** — generated report/control-path commands now use
  real CLI flags for `attack gmsa`, `attack laps`, constrained delegation, and
  ESC1 enrollment context.
- **Password fallback consistency** — commands that still parsed `--password`
  as mandatory now accept `@file:`, `$ADHAMMER_PASSWORD`, and TTY prompt like
  the rest of the CLI.
- **Release truth pass** — README / VECTORS / local validation ledger now align
  with the actual local code and validation status instead of the stale 1.3.10
  public surface.

## [1.4.1] — 2026-08-24

The **"grandiozno"** feature release. 12 workstreams + 5 refactor passes.
Skips permanently-yanked 1.4.0 slot on crates.io. Live-validated against
Windows Server 2022 + 2025 DCs (both `testlab.local` forests).

### Added — feature workstreams

**WS-1 MSSQL** — `attack mssql` subcommand: TDS 7.4 over NTLM, `--query`,
comma-separated `--execute-as` chain (LIFO push, REVERT unwind on both
paths), `--database`, `--port`, `--tsv`. Requires `ms-tds 0.1.1`
(new `run_query` / `impersonate` / `revert_to_self` + SQL builders).
Row-content rendering waits on ms-tds ROW decoder.

**WS-2 DCShadow modern (DRSUAPI path)** — bypasses 2019+ LDAP
"system-owned attribute" hardening. `attack dcshadow --drsuapi
--prep <rogue-dsa>` (IDL_DRSAddEntry opnum 17), `--drsuapi --push
--target <sam> --attr <name> --value <val>` (IDL_DRSReplicaAdd
opnum 5 + AddEntry modify), `--drsuapi --cleanup`. LDAP-path prep
retained with "≤ Server 2016 only" doc note. Requires `ms-drsr 0.2.0`.

**WS-3 cross-forest `--foreign-sid`** — `attack golden --foreign-sid
<SID>[,<SID>…]` injects foreign SIDs into PAC's KERB_SID_AND_ATTRIBUTES
(MS-PAC 2.5, Attributes = 0x7). On a trusting forest with SID filtering
DISABLED, the KDC accepts the injected principal. Requires
`ms-pac-forge 0.1.3`.

**WS-4 Kerberos sealed bind primitives (Phase 1 only)** — dcerpc now
exposes `RPC_C_AUTHN_GSS_KERBEROS` (0x10), PDU framers
(`build_bind_auth_kerberos` / `build_auth3_kerberos` /
`build_request_sealed_krb`), an RFC 4121 `WrapToken` header codec,
and a `KrbSealer` trait. Phase 2 concrete `AesCtsHmacSha1KrbSealer`
+ `RpcTcp::bind_sealed_kerberos` wire deferred to 1.4.2. dcerpc 0.3.0
primitives stay unpublished until Phase 2 lands.

**WS-5 DACL Attacks II** — 5 new `attack abuse` actions extending the
DACL chapter to full CAPE coverage: `write-owner`, `write-dacl`,
`set-primary-group`, `gpo-link-modify`, `allowed-to-act` (alias of
write-rbcd). All Collector::read/write helpers hand-rolled without a
windows-sddl bump.

**WS-6 Shadow Credentials management** — `attack shadowcred --list`
(parse KEYCREDENTIALLINK_BLOB entries — DeviceId + created + usage +
source columns), `--remove <DeviceId>`, `--clear` (with `--yes` gate).

**WS-7 Password spray lockout protection** — `attack spray
--lockout-threshold N` + `--lockout-window <secs>`. Per-user sliding-
window failure counter; skip users that trip the guard; final tally
on run end.

**WS-8 UAC flag management** — new `AbuseAction::SetUacFlags`.
Comma-separated `--value` OR's bits into `userAccountControl`
(DONT_REQUIRE_PREAUTH / TRUSTED_FOR_DELEGATION /
TRUSTED_TO_AUTH_FOR_DELEGATION / DONT_EXPIRE_PASSWORD /
ACCOUNTDISABLE / PASSWD_NOTREQD). Live-verified on DC01:
`0x00010200 → 0x00410200` with DONT_REQUIRE_PREAUTH. PFX export
deferred to 1.4.2.

**WS-9 Multi-format report output** — `scan --out <path>` now infers
`.md` / `.txt` formats. New `--out-all <dir>` writes all four
(`report.json` / `report.md` / `report.html` / `report-summary.txt`)
in one pass. Markdown has TOC + per-severity sections; plaintext
summary shows top-N findings (default 10). Zero new deps
(no chrono — hand-rolled Hinnant civil-from-days).

**WS-10 Composite attack-chain narrative** — new
`crates/report/src/composite.rs` cross-references findings post-scan
to emit English composite chains. 4 chains ship in 1.4.1
(Coercion + ESC8 → DA cert / ESC1 → PKINIT / MAQ + ESC8 → full relay /
DCSync + Shadow Cred → replicate). Rendered in JSON
(`composite_chains` array), HTML (top section), MD (`## Attack chains`),
and TXT summary. Extend as more checks land (SMB-signing check needed
for the other 6 chains).

**WS-11 Anonymous fingerprint mode** — `scan --anonymous` skips the
authenticated collection and runs port scan (12 ports) + null-session
SMB negotiate + raw UDP SRV query for `_ldap._tcp.dc._msdcs.<domain>`
+ RootDSE anonymous fingerprint. Live-verified against DC01
(4 findings across 4 sources; all 4 report files written).

**WS-12 `adhammer setup krb5` — interactive krb5.conf generator.**
`adhammer setup krb5 --realm <REALM> --dc <IP>` (both optional; prompts
via dialoguer if missing; discovers DC via SRV if `--dc` not given).
Emits a working krb5.conf to `~/.krb5.conf` (Unix) or
`%APPDATA%\krb5.conf` (Windows). Prints the `KRB5_CONFIG=…` export line.

### Added — helper prep (CLI wiring in 1.4.2)

**WS-13 prep — `adhammer_collector::dns_record`** — public
`build_a_record()` DNS_RPC_RECORD builder (MS-DNSP 2.2.2.2.1) so
downstream users can build their own ADIDNS write tooling on it.
Full `attack dns` CLI (add-a / modify-a / tombstone / delete)
lands in 1.4.2.

### Changed — internal refactor (no CLI surface change)

- **arch-0** — `cli/src/main.rs` 5670 → 832 lines (−85%). 35 handlers
  extracted into `cli/src/{attacks,enums,dumps,checks}/` subtrees
  across 4 batches. Zero behavior change.
- **arch-1** — `cli/src/adcs_relay.rs` → `cli/src/attacks/adcs_relay.rs`
  for subtree consistency.
- **ux-0** — `SmbAuth` / `LdapAuth` / `OptAuth` `#[derive(clap::Args)]`
  structs flattened into 16 subcommand Args via `#[command(flatten)]`.
  Removes ~300 LOC dedup; `--help` surface byte-for-byte identical.
- **ux-2** — unified `--target` classifier + resolver helpers in
  `cli/src/target.rs`.
- **ux-7** — grouped interactive menu (Recon / Creds / Lateral /
  Persist / Session) with two-level Select + `← Back`.

### Compatibility notes

- **1.4.0 is permanently yanked on crates.io.** Numbering skips to 1.4.1.
- **MSRV stays at 1.87** (bumped in 1.3.10; no further bump in 1.4.1).
- **Sibling crate bumps required by 1.4.1:** `ms-pac-forge 0.1.3`,
  `ms-drsr 0.2.0`, `ms-tds 0.1.1` (all published on crates.io).
- **`dcerpc` stays at 0.2.x on crates.io for 1.4.1.** The 0.3.0
  Kerberos sealed-bind primitives (WS-4 Phase 1) ship together with
  Phase 2 concrete crypto in 1.4.2.

### Deferred to 1.4.2

- WS-1 Phase 3 live query (needs MSSQL Express install on 2025server1)
- WS-2 Phase 3 live DCShadow push (needs benign-attr capture-then-restore)
- WS-3 cross-forest positive validation (needs inter-realm trust — 1.4.2 WS-E lab)
- WS-4 Phase 2 (concrete AES-CTS-HMAC-SHA1-96 sealer + rpc bind wire)
- WS-8 Phase 2 (PFX export on shadowcred — real PKCS#12 out of scope)
- WS-13 `attack dns` CLI (helper prepped; CLI in 1.4.2)
- WS-14 `--allow-cross-trust` on `attack constrained` (needs cross-realm TGS plumbing)
- dcerpc 17 pre-existing clippy warnings cleanup (blocks dcerpc 0.3.0 publish)
- WS-F SCCM + SCOM enum, WS-G ADIDNS DELETE, WS-H krb5.conf enhancements

### Carry-over detail from late 1.3.10 stabilization
  extending the DACL-write chapter to full CAPE coverage:
  - `write-owner` — rewrite Owner SID in `nTSecurityDescriptor`
    (SD_FLAGS-controlled read, in-place owner splice, write-back).
  - `write-dacl` — prepend a GENERIC_ALL allow-ACE for `--value` at DACL
    position 0. Hand-rolled ACE builder + DACL splice (no `windows-sddl`
    change needed).
  - `set-primary-group` — write `primaryGroupID` to a RID (numeric) or
    a group's `objectSid` last sub-authority (sAMAccountName resolution).
  - `gpo-link-modify` — append `[LDAP://cn={GUID},cn=policies,cn=system,
    <base>;0]` to an OU's `gPLink`.
  - `allowed-to-act` — alias of `write-rbcd` (same
    `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, red-team naming).
- **Global `--dry-run` on `attack abuse`** — every write action (new + existing)
  now gates on `--dry-run`, printing `[dry-run] would write attribute=… target=…
  value=…` (SDs as hex) and returning before any `Collector::modify_*` /
  `write_binary` call. Safe against a live DC.
- **`Collector::read_binary` / `read_text` / `modify_replace`** — read a
  single binary attribute (SD_FLAGS-controlled base read for
  `nTSecurityDescriptor`), read a text attribute, and Replace a single-value
  text attribute — supporting the new DACL / `primaryGroupID` / `gPLink` flows.

## [1.3.10] — 2026-08-23

Hardening + UX pass driven by an outside multi-agent code review that
surfaced 37 findings; 33 landed in this release (P0 + P1 + most P2). No
new attack surface, no wire-format changes — a "trust me on the wire"
maintenance release.

### Added
- **`--password @file:/path/to/pw`** — read the password from a file
  (trailing `\r\n` trimmed) instead of passing it on argv. Applies to
  every subcommand that takes `--password`.
- **Interactive password prompt** — when `--password` is omitted, no
  `$ADHAMMER_PASSWORD` env var is set, and stdin is a TTY, the CLI now
  prompts for the password with echo off (via the existing dialoguer
  dep — no new dependency).
- **`scan --out <path>`** — write the report to a file with format
  inferred from the extension (`.json`, `.html`), instead of only stdout.
- **`--yes` on bulk destructive actions** — `attack dcsync --all` and
  `attack samr --dump-secrets` now require `--yes` (or a non-TTY stdin)
  to run non-interactively. `--limit N` also added to `dcsync --all` to
  bound blast radius during a run.

### Changed
- **`attack pth` → `attack ptt`** — the subcommand does pass-the-ticket
  (S4U-based), not pass-the-hash. `pth` remains as a hidden alias so
  existing scripts keep working; it just doesn't show in `--help`.
- **Typed value_enums on three CLI flags** — `attack coerce --pipe`,
  `attack abuse --action`, and `attack relay --target` now reject
  unknown values at parse time with the accepted set instead of
  running past an LDAP/SMB connect only to bail late. `--help` now
  renders per-value docstrings under each flag.
- **Cleartext session refuse-by-default** — on non-Windows hosts where
  DPAPI is unavailable the session file would previously silently write
  in cleartext. It now refuses unless `ADHAMMER_ALLOW_PLAIN_SESSION=1`
  is explicitly set (lab use). Windows behaviour is unchanged
  (CryptProtectData wrapping stays default).
- **Session file created 0600 atomically on Unix** (`O_CREAT|O_EXCL`
  + mode 0600) — closes the TOCTOU window where the file briefly
  existed at umask default before permissions were tightened.

### Fixed
- **DRSUAPI wire hardening** — three bounded-alloc preflights
  (`ptmc`/`amc`/`vmc`) against the remaining stub with 12/12/8-byte
  per-entry sizes, plus a panic-safety fix in `read_dsname_rid`
  (SubAuthorityCount validated to 1..=5, buffer read uses
  `.get(off..off+4).ok_or_else(...)` instead of unchecked slice +
  `unwrap`). Regression tests cover zero-count and oversized-count
  inputs and assert no panic.
- **Registry hive `ri` recursion** — the subkey walker was
  recursive with no cycle guard, so a crafted hive could stack-overflow
  or spin forever on a cyclic `ri` list. Rewritten as an iterative BFS
  with a `HashSet<u32>` visited set and a `MAX_VISITED = 65_536` cap.
- **Kerberos non-ASCII inputs no longer panic** — `krb_string`,
  `principal`, `build_as_req`, `build_as_req_etype`, and `build_tgs_req`
  all return `Result` and reject non-IA5String (non-ASCII) input at the
  boundary instead of panicking inside `picky-asn1`. RFC 4120 requires
  IA5String for principal components. Regression tests cover Cyrillic
  and Chinese input.
- **Guided-mode credential leak in reports** — the "here's the exact
  command I ran" line printed in `adhammer` guided mode was leaking
  `--password`/`--nt-hash`/`--*-aes256` values into the on-disk
  transcript. `redacted_cmd()` now redacts 13 sensitive flag names
  before rendering. 4 unit tests cover the redaction.

### Security
- **`$ADHAMMER_PASSWORD` env-var fallback** on every `attack` handler
  and on the three `enum sessions|wkssvc|hku` handlers when
  `--password` is unset — CI can now inject the credential without
  writing it to argv. Also threaded through the `abuse` handler's
  `Option<String>` variant.
- **`@file:PATH` password refs + TTY prompt** (see Added) close the
  argv-leak vector completely for interactive use. Live-validated
  against Windows Server 2025 with a real DA credential on
  `attack dcsync`, `attack coerce`, and `enum sessions`.

### Refactor (internal — no CLI change)
- ADCS ESC registry decision layer (~230 LOC) moved from
  `cli/src/esc_registry.rs` into the reusable
  `adhammer_checks::esc_registry` module; the CLI file is now a thin
  transport wrapper. Enables downstream consumers of the checks crate
  to reuse the ESC6/7/10/11/16 decision code.

### CI
- Clippy is now gated as `-D warnings` (was `|| true`).
- Test matrix expanded to Ubuntu + Windows + macOS.
- MSRV verify job reads `rust-version` from `Cargo.toml` and pins the
  toolchain accordingly.

### Docs
- CHANGELOG backfilled with entries for 1.3.1 through 1.3.9 (previously
  only the most-recent release was documented).

## [1.3.9] — 2026-08-20

### Added
- **Session-hunt trio** — three complementary "who is on this box" primitives:
  `enum sessions` (MS-SRVS `NetrSessionEnum`, incoming SMB sessions),
  `enum wkssvc` (MS-WKST `NetrWkstaUserEnum` level 1, logged-on users — needs
  local admin), `enum hku` (MS-RRP registry walk over `\winreg` returning the
  S-1-5-21 SIDs of loaded profile hives — often works without local admin).
  Dedup + machine-account filter on by default.
- **Global `--json` envelope** on every `attack`/`enum`/`dump` subcommand — output
  wraps in an `AttackResult` envelope that pipes cleanly into `jq` and CI.
- **DPAPI-encrypted saved sessions on Windows** — `~/.config/adhammer/session.json`
  uses `CryptProtectData` with an `ADHS` magic header; `--old` reuses cached creds,
  `--no-save` keeps them off disk.
- **ADCS scan pack** — `scan` now runs ESC6, ESC7, ESC8, ESC10, ESC11, ESC16 as
  part of the default sweep via MS-RRP `\winreg` probes plus an HTTP probe for
  ESC8 web enrollment.
- New `dcerpc` modules: `wkssvc` (`NetrWkstaUserEnum`) and `rrp::logged_on_sids`
  (HKU walk).

### Fixed
- **Wire-stack bounded-alloc audit** — every attacker-controlled `u32` that fed
  `Vec::with_capacity` in the wire decoders is now preflighted against the
  remaining stub:
  - `srvsvc::decode_session_enum` — `entries_read × 16` preflight.
  - `rrp::decode_query_info_class` — `actual × 2` preflight.
  - `rrp::decode_enum_key` — `actual × 2` preflight.
  - `wkssvc::decode_wksta_user_enum` — `entries_read × 16` preflight.
  Regression tests feed `0xFFFFFFFF` and assert `RpcError::Protocol`. Requires
  `dcerpc 0.2.5`.

### Live-validated
Full stack against Windows Server 2022 and Server 2025 DCs.

## [1.3.8] — 2026-08-18

### Added
- **DCShadow phase-1 prep** — `attack dcshadow --prep <name>` registers a rogue
  `nTDSDSA` object under Configuration NC (idempotent; safe to re-run after
  partial failure). `attack dcshadow --cleanup <name>` removes it. Full push
  (phase 2) is not yet implemented. **Note:** the LDAP path is blocked by
  Server 2019+ "system-owned attribute" hardening; the docstring on the
  subcommand carries that caveat. Server 2016 and older accept the LDAP path.
- `Collector::delete_object` — LDAP delete primitive that DCShadow cleanup
  uses; also fills a general-purpose gap in the collector.

### Fixed
- Requires `dcerpc 0.2.4` — wire stack hardened against three bounded-alloc
  vectors uncovered in review of the incoming external PR (srvsvc + two rrp
  sites).

## [1.3.7] — 2026-08-16

### Added
- **AD CS active pack extension** — `attack certipy` (renamed to
  `attack icpr-esc1` in 1.3.10) gains `--esc` switch:
  - ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 SAN injection (live-validated).
  - ESC15 — EKUwu / CVE-2024-49019 Application Policies (live-validated).
  - ESC3 — Enrollment Agent → on-behalf-of (offline test passes; live needs
    EA cert setup).

### Fixed
- **4 library security patches** ship as pinned deps:
  - `ms-icpr 0.1.2` — fix `esc3.rs` PKIData `[0]` IMPLICIT vs EXPLICIT tagging
    (Windows CAs were rejecting the request shape).
  - `ms-pac-forge 0.1.2` — bounded-alloc preflight in `parse_pac` (caps
    attacker-controlled `c_buffers u32` at `(pac.len() - 8) / 16`).
  - `ntlm-relay 0.1.2` — drop duplicate `Host` / `Connection` / `Content-Length`
    headers on `certsrv` send sites.
  - `ms-csra 0.1.1` — delete broken `GetCAProperty` path (opnum 3 was
    `SetExtension`, not `GetCAProperty`); expose only `GetConfigEntry` on
    `ICertAdminD2` opnum 44.

### Pulled
- `enum ca-config` command — `ICertAdminD2` UUID + opnum 44 rejected by live
  DC01; needs Wireshark trace of a real `certutil -config` before re-adding.

## [1.3.6] — 2026-08-15

### Fixed
- Fix #3 (assorted patches rolled in).

## [1.3.5] — 2026-08-15

### Changed
- Workspace version bump + README refresh — no user-visible functional change;
  clears drift after the pre-1.4.0 revert.

## [1.4.0] — 2026-08-13 (YANKED)

Yanked on crates.io. Version number **retired**; the next major bump will be
`1.4.1`. Content was rolled back by commits `219a415` + `e5a8163` before
downstream users saw a working release.

## [1.3.4] — 2026-08-13

### Fixed
- `check adcs` returned 0 templates because `Collector` `ATTRS` missed the
  `msPKI-Cert-Template-OID` required by `ms-crtd`. Live-validated fix.

## [1.3.3] — 2026-08-09

### Added
- Wire ADhammer onto `ms-crtd` + `ms-icpr` + `ms-gkdi` — the AD CS ESC rule
  pack + `dump laps` / `dump gmsa` / `attack certipy` land in the CLI.

### Fixed
- CI fix for `[patch.crates-io]` — CI was picking up path-deps that don't
  exist for CI users.

## [1.3.2] — 2026-08-09

### Changed
- Consume `ms-pac-forge 0.1.1` from crates.io + wire onto the 17-crate
  icedracon foundation set (all extracted from adhammer, now published
  standalone). Adhammer is now a workspace on top of published protocol
  crates, not a monorepo.

## [1.3.1] — 2026-08-06

### Fixed
- BadSuccessor (Server 2025 dMSA) bug fix.

### Changed
- Consume `smb2-client 0.2.1` — brings `TCP_NODELAY` win on the SMB transport;
  measurable latency drop on many-small-PDU workloads (RPC-heavy scans).
- Benchmarks refreshed against the new transport perf.

## [1.2.0] — 2026-08-02

### Added
- **WMI / DCOM remote execution** (`attack wmiexec`) — a from-scratch MS-DCOM + MS-WMIO stack:
  `RemoteCreateInstance` activation → OXID-binding resolve → object-ORPC (`PFC_OBJECT_UUID`) →
  `IWbemLevel1Login::NTLMLogin` → `IWbemServices::ExecMethod Win32_Process.Create`. Runs an arbitrary
  command detached under WmiPrvSE, captures output over C$; **password or pass-the-hash**. No service
  or scheduled task (distinct host telemetry from `exec`/`atexec`). Live-verified vs a Windows DC.
- **Hygiene checks → 41 total** — privileged-account, stale-object and password-policy rules
  extending the base hygiene rule set.
- **`enum esc`** — AD CS ESC6/7/10/11/16 over a from-scratch MS-RRP remote-registry client (takes ESC
  coverage to 15/16); **`enum posture`** — LDAP signing / channel binding / Spooler relay-enablers.
- **`attack zerologon`** — CVE-2020-1472 **safe detection** (never resets the machine password).
- **SOCKS5 pivot** (`--socks`) routing all outbound TCP — SMB, RPC/DCSync, LDAP collection, KDC, WinRM,
  and the network sweep — through a proxy with proxy-side DNS.
- **Legacy-DC support matrix** — live-validated on Server 2012 R2 / 2016 / 2019 / 2022 in addition to
  fully-patched 2025 (golden ticket KDC-accepted on every version).
- **Guided exploitation** (`adhammer auto`, + interactive "Guided" menu item) — scan → correlate
  findings → for each weakness **ask the operator "validate + capture a PoC?"** → run the matching
  attack (Kerberoast, DCSync, gMSA read, AD CS ESC1) → capture the exact command + output as
  evidence → write a **Markdown assessment report**. Declined and non-auto-validatable findings are
  still documented in the report (marked not-exercised), so it's the complete picture. Colored,
  severity-coded terminal output; `--yes` runs unattended. Live-validated vs Server 2025 (report
  captured a real DCSync krbtgt-hash PoC).
  - **Proof-based validation:** a finding is marked "validated" only when the specific evidence is
    present (an actual `$krb5tgs$`/`$krb5asrep$` hash, a replicated `krbtgt` secret, an `ISSUED`
    cert), checked against the full output — otherwise "attempted." No exit-code false positives.
  - **Opportunistic active checks** beyond the passive scan: LAPS local-admin read and AD CS ESC8
    web-enrollment probe, added to the report only when a weakness is confirmed (live-validated: a
    seeded LAPS password was recovered into the PoC). Coercion/relay deferred (need a capture listener).

### Changed
- **TLS backend is now a Cargo feature — rustls by default.** The default build uses rustls with
  bundled AWS-LC (no `openssl-sys` or system TLS library), so it cross-compiles and static-links
  (a fully static `x86_64-unknown-linux-musl` binary). The native-TLS build selects the
  OpenSSL/Schannel backend for legacy DCs whose LDAPS certs use SHA-1 handshake signatures.

### Fixed
- **SOCKS pivot now covers LDAP collection** — ldap3 owns its own connect, so a local forwarder
  bridges it through the proxy (the `--socks` help claimed LDAP coverage that the collector bypassed).
- **S4U / service-ticket etype robustness** — `get_service_ticket` offers RC4 alongside AES256 (an
  overpass-the-hash TGT is RC4); `pa_for_user` rejects a non-AES256 TGT key with a clear error.

### CI
- **Release workflow** — cross-compiled binaries (x86_64 linux-musl static / linux-gnu / windows-msvc,
  aarch64 macOS) built and attached to the GitHub release on tag push.

## [1.1.0] — 2026-07-29

### Added
- **AD CS audit ESC5 / ESC14 / ESC15** — three new passive (LDAP-only) certificate-services checks:
  ESC5 (broad-principal Write/Owner over a CA object → PKI reconfiguration), ESC14 (weak explicit
  `altSecurityIdentities` mapping — Subject-only / Issuer+Subject / RFC822), and ESC15 / EKUwu
  (CVE-2024-49019 — any enrollable schema-v1 template allows application-policy injection). Takes
  ADhammer's ESC coverage to 10/16. ESC14 + ESC15 live-validated vs Server 2025 (ESC15 on the lab's
  v1 templates; ESC14 on a seeded weak mapping). ESC6/7/10/11/16 remain (need a CA/DC registry read).
- **AD CS enumeration + ESC8 detection** (`enum adcs`) — list enterprise CAs (name + host) from the
  Configuration NC, then actively probe each CA's `http://<host>/certsrv` web-enrollment endpoint:
  a cleartext NTLM/Negotiate 401 is flagged as ESC8 (relayable — no TLS ⇒ no channel binding). ESC8
  is relay-only so it can't be decided from the passive LDAP snapshot; this is the active check.
  Classifier unit-tested; live-validated vs Server 2025 (CA discovered; ESC8 negative without web
  enrollment, positive once the Web-Enrollment role is present). ESC11 (unencrypted ICPR) detection
  is noted as a follow-up (needs a CA config read).
- **ADIDNS enumeration** (`enum dns`) — adidnsdump-equivalent: read every AD-integrated DNS zone
  and record from the `DomainDnsZones`/`ForestDnsZones` (and legacy `System`) partitions over LDAP,
  with a from-scratch `DNS_RPC_RECORD` parser (A/AAAA/CNAME/NS/SOA/SRV/MX/TXT/PTR; unknown types as
  hex). Flags wildcard (`*`) nodes — an ADIDNS/mitm6 name-hijack surface — and tombstoned records.
  Interactive menu entry. Live-validated vs Server 2025 (zones + all record types + wildcard).
- **WinRM exec** (`attack winrm`) — run commands over WS-Management (5985/HTTP) with NTLM auth
  and MS-NLMP message encryption ("SPNEGO session-encrypted" multipart), on a from-scratch raw-TCP
  HTTP client (no external WinRM/HTTP stack). Full shell lifecycle (Create → Command → Receive
  loop → Signal → Delete), stdout/stderr capture, exit-code propagation, and pass-the-hash
  (`--nt-hash`). Quieter than SVCCTL — no 7045 service-install event. Interactive menu entry added.
  Live-validated vs Server 2025 (password + PtH, stdout/stderr, exit codes).
- **Session hygiene** — top-level `--no-save` (never write creds to disk) and a "Wipe saved
  session" interactive menu item, for use on a client/engagement box.
- **LAPS read** (`attack laps`) — recover local-administrator passwords over LDAPS. Reads both
  legacy Microsoft LAPS (`ms-Mcs-AdmPwd`, cleartext) and Windows LAPS (`msLAPS-Password`, JSON);
  `--target <HOST$>` for one host or omit it to sweep every computer whose LAPS attribute you can
  read. The DPAPI-NG-encrypted `msLAPS-EncryptedPassword` is surfaced but not yet decrypted.
  Interactive menu entry added. Live-validated vs Server 2025 (Windows LAPS, plaintext mode);
  degrades cleanly to "no LAPS readable" on DCs without the LAPS schema. First ROADMAP v1.1 item.

## [1.0.1] — 2026-07-29

### Fixed
- **Scan/roast/all LDAP actions failed on real DCs with a bare username** (`administrator`) —
  a bare sAMAccountName is rejected by simple_bind (rc=49, `data 52e`). The collector now reads
  the domain from RootDSE and auto-qualifies a bare name to a UPN (`user@domain`); anything
  already qualified (`DOMAIN\user`, UPN, full DN) is untouched. Bind errors now name the identity
  tried and suggest the qualified form instead of a bare "bind failed". Verified live vs Server 2025.
- **Interactive network sweep defaulted to `10.0.0.0/24`**, which sweeps an empty range on most
  engagements. It now defaults to the DC's own /24.

## [1.0.0] — 2026-07-28

First stable release. A single Linux-native Rust binary that both **audits** Active Directory
and **exploits** it, on a from-scratch DCE/RPC · NTLM · SMB2 · Kerberos stack. Every offensive
capability below is live-validated end-to-end against a fully-patched **Windows Server 2025** DC.

### Audit
- 33 checks across four AD hygiene categories (privileged accounts, trusts, stale objects,
  anomalies), with per-finding MITRE ATT&CK mapping.
- In-process control-path graph (reverse-Dijkstra to Tier-0); works as a
  low-privileged user via the LDAP `SD_FLAGS` control.
- BloodHound CE ingest bundle export (`scan --bloodhound`).
- SYSVOL / GPP cpassword (MS14-025) and GptTmpl.inf policy analysis.

### Offense (live-validated vs Server 2025)
- **Roasting** — AS-REP and Kerberoast (RC4 13100 + AES 19700); requests RC4 **and** AES so
  AES-only services still yield a ticket.
- **Password spray** + user/AS-REP-roastable enumeration.
- **LDAP-object abuse** — add-spn, add-member, set-password, write-rbcd, Shadow Credentials
  (`msDS-KeyCredentialLink`).
- **RBCD** and **constrained delegation** — full S4U2Self → S4U2Proxy chains.
- **Shadow Credentials PKINIT** — key-trust TGT, incl. the Server 2025 `paChecksum2`
  (SHA-256 over the KDC-REQ-BODY) requirement.
- **Coercion** — PetitPotam / MS-EFSR and PrinterBug / MS-RPRN.
- **DCSync** — single-object and full-domain, over sealed DRSUAPI; extracts NT hashes **and**
  Kerberos keys (AES256/128, RC4, and Server 2025's RFC 8009 AES-SHA2 etypes 19/20).
- **Golden / silver tickets** — from-scratch PAC (`KERB_VALIDATION_INFO` NDR + SERVER/KDC
  signatures + `PAC_REQUESTOR`/`PAC_ATTRIBUTES` for KB5020805). Forged Domain-Admin TGT accepted
  by a fully-patched 2025 KDC.
- **Pass-the-ticket** — Kerberos AP-REQ over SMB2 (GSS/SPNEGO); run commands as the impersonated
  identity. Verified: forged ticket → `NT AUTHORITY\SYSTEM` on the DC, from Kali.
- **Pass-the-hash** — `--nt-hash` on exec/secretsdump/enum.
- **Overpass-the-hash** — RC4-HMAC AS-exchange turns an NT hash into a Kerberos TGT.
- **RC4 golden/silver** — `--rc4` (KERB_CHECKSUM_HMAC_MD5 PAC signatures) for RC4-enabled
  (Server ≤2022) DCs.
- **Exec / secretsdump** — SVCCTL LocalSystem RCE with `C$` output capture; offline SAM/LSA/DCC2
  from reg-saved hives.
- **gMSA read**, **AD CS ESC1**, **NTLM relay** (SMB → LDAP shadow-cred), **capture/poison**
  (NTLMv2 → hashcat, LLMNR/NBT-NS).

### Protocol stack — published as standalone crates
Extracted from this repo as reusable MS-* protocol crates:
[`windows-sddl`](https://crates.io/crates/windows-sddl),
[`ntlmssp`](https://crates.io/crates/ntlmssp),
[`smb2-client`](https://crates.io/crates/smb2-client),
[`dcerpc`](https://crates.io/crates/dcerpc). ADhammer consumes them.

### Interface
- Guided interactive TUI (`adhammer`): user → password/NT-hash → domain → DC, then all 21
  actions; golden/silver/pth auto-fetch the key (DCSync) and domain SID (LSAT) from the session.
- Power-user subcommands: `scan`, `enum {samr,lsa,net}`,
  `attack {roast,spray,abuse,coerce,rbcd,constrained,dcsync,exec,secretsdump,gmsa,esc1,golden,silver,pth,asktgt,capture,poison,relay}`.

### Quality
- ~110 tests across the workspace + extracted crates (spec vectors + round-trips), a live-DC
  integration harness, and GitHub Actions CI. Zero clippy/build warnings. Parser fuzzing.

### Known limitations
- Live validation is against Server 2025 only; the 2016/2019/2022 matrix is not yet recorded.
- RC4 golden→TGS completion needs an RC4-service DC (≤2022); on 2025 the forged RC4 TGT is
  accepted but the service ticket is refused (KDC policy).
- BloodHound export is confirmed to ingest + analyze in **BloodHound CE** (the domain loads as a
  queryable graph); not yet exercised across every edge type.
- Open vectors (roadmap): noPac, Zerologon, ADCS ESC5–11, DCShadow, LAPS, trust-key dumping —
  see [VECTORS.md](VECTORS.md).

Authorized testing / research / education only — see [SECURITY.md](SECURITY.md).
