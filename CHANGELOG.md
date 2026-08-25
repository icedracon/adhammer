# Changelog

All notable changes to ADhammer are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); this project uses SemVer.

## [Unreleased]

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
- **TLS backend is now a Cargo feature — rustls by default.** The default build is pure-Rust (no
  `openssl-sys`, no system libraries), so it cross-compiles cleanly and static-links (a fully static
  `x86_64-unknown-linux-musl` binary). `--no-default-features --features tls-native` selects the
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
