# ADhammer 1.5.0 — hard plan (post-1.4.9-SEC-close + capability push)

Written 2026-08-31, revised 2026-09-01 after the SEC-1 remediation
batch landed in 1.4.9 (`docs/CHANGELOG.md` §1.4.9 Security, commit
`1fd4b80`). Score target: **95/100 self-reachable ceiling.** The
final 3 points (external audit + 6-month track record + independent
red-team attestation) stay explicitly out of this plan.

**1.5.0 restores normal ship cadence.** 1.4.9 shipped LOCAL-only per
operator directive. 1.5.0 goes back to bottom-up crates.io publish +
tag + GitHub release. If a sibling crate has a live RustSec advisory
during 1.5.0's cycle, that specific publish stays permitted mid-cycle
per the same-cycle-mitigation rule.

**SEC-1 closed in 1.4.9.** The `WS-PROTOCOL-SECURITY` workstream that
sat at the top of this plan through 1.4.9's shakedown is now
historical — every High and Medium finding from the SEC-1 review
landed in 1.4.9. This plan retains the workstream heading below as a
receipt-with-commit-pointer; new 1.5.0 scope starts with
`WS-DEPS-MAJORS`.

**Ship policy — 1.5.0 stays LOCAL initially.** Same rule as 1.4.9. When
the plan says "publish sibling crate X 0.y.z", that means the git tree
gains the code + version bump; the actual `cargo publish` waits for an
authorized cycle. Only exception is if a sibling-crate bump is required
to remove a live RustSec advisory (in which case that one publish is
justified).

## Bug-carry from 1.4.9 (append-only during 1.4.9 shakedown)

Any bug found in the 1.4.9 tree that isn't a same-cycle fix lands here.
Every entry: title + severity + reproducer path + landing commit or
"pending" + which 1.5.0 workstream absorbs the fix.

### SEC-1 — protocol-library security review remediation

**Severity:** release blocking until the High findings are resolved.

**Source review:** `ADHAMMER_PROTOCOL_LIBRARY_SECURITY_REVIEW_1.4.9.md`
(2026-09-01, canonical revision `9752c8f29da3b5a00f6ebc448591a4f5a44d5e9c`).

**Scope:** LDAP BER/message bounds and integrity (AH-001/002/003), WinRM
response budgets and checked chunk framing (AH-004/005), secret ingress
(AH-006), write-DACL and Windows-SDDL correctness (AH-007/WS-001/WS-002).

**Landing policy:** local-only in 1.5.0 until the full regression matrix is
green. Each landing must add a regression test for the exact malformed input
class, preserve the authorized-testing boundary, and update the review with
the commit plus residual risk.

**Exit criteria:** no High review findings remain open; every untrusted parser
has an allocation budget and no-panic regression coverage; sensitive LDAP
writes require a verified integrity channel; and the final review is rerun on
the exact release commit.

| Finding | Local 1.5.0 state | Evidence |
| --- | --- | --- |
| AH-001 / AH-002 | fixed | LDAP rejects truncated, indefinite, non-canonical, oversized and cross-container BER values; it caps messages and times out I/O. |
| AH-003 | mitigated | Direct password-authenticated LDAP-389 writes are refused pending verified LDAPS or a negotiated SASL integrity layer. Relay steps remain explicitly separate. |
| AH-004 / AH-005 | fixed | WinRM has header, wire-body, decoded-body, chunk-line, chunk-count and command-output limits with checked framing arithmetic. |
| AH-007 | fixed | Write-DACL validates declared ACL/ACE boundaries before rebuilding an ACL. |
| WS-001 / WS-002 | fixed locally | The sibling `windows-sddl` checkout models DACL presence/NULL semantics and validates ACL/ACE bounds; Cargo patches every workspace and transitive user to that same local implementation. |
| AH-006 | fixed | `SecretString` (zeroize-on-drop, redacted `Debug`/`Display`) at every CLI ingress via `shared_args::{SmbAuth,LdapAuth,OptAuth}`, `winrm::Secret::Password`, `shadowcred::pfx_password`, `guided::GuidedArgs.password`, and the 3 `dialoguer::Password` prompt sites in `interactive.rs`. Child-argv literal-pw propagation refused: `guided.rs` passes `env:ADHAMMER_GUIDED_PASSWORD` verbatim as the argv `--password` value and sets the env var on the `Command` before spawn — the literal never appears in argv. `SecretString::FromStr` accepts `env:VAR`, `@file:PATH`, or literal (deprecated). |

### CI-1 — `package-check` cannot run per-commit under "all local"

**Severity:** low (CI process, not code correctness).

**Repro:** `cargo package -p adhammer-graph --allow-dirty --no-verify` on
the 1.4.9 tree with no 1.4.9 tag published to crates.io.

**Symptom:** `failed to select a version for the requirement
adhammer-core = "^1.4.9"` — cargo strips path deps and resolves internal
`version = "1.4.9"` refs against crates.io; 1.4.9 is not on the index
during local-only cycles.

**Same-cycle mitigation (landed 1.4.9):** `package-check` job gated to
tag pushes + `workflow_dispatch`; new `manifest-sanity` job
(`cargo metadata --locked`) covers per-commit manifest sanity.

**1.5.0 workstream:** WS-EVIDENCE-BUNDLE (folds a full pre-publish
package check into the release step) + WS-STABILITY-1-0 (once
bottom-of-stack siblings hit 1.0, publishing frequency drops and the
gate-on-tag policy is a natural fit).

### BUG-19 — `pac_credential_info` fuzz-found panic (fifth of the picky-krb class)

**Severity:** low (only reachable when a compromised KDC returns a
malformed PAC_CREDENTIAL_INFO; `pac_credential_info` outer walk still
converts panic → err via caller `catch_unwind`, but the fuzz target
runs the parser directly and asserts no-panic).

**Repro:** CI run
https://github.com/icedracon/adhammer/actions/runs/33427141674 job
`cargo-fuzz (nightly, short)`; crash artifact
`fuzz/artifacts/pac_credential_info/crash-2f1c7c633177a2bf96d2c4a5b86333f19f55385b`
(uploaded starting with the ci.yml commit that added the upload step).

**Root cause:** same class as BUG-16/17/18 — `picky-krb 0.9.6`'s
AES-CTS-HMAC-SHA1 decrypt path calls `generic_array::GenericArray::
from_slice` on a slice whose length the callsite hasn't proved matches
the expected block size. Some shape leaks past `AES_MIN = 44` +
`RC4_MIN = 40`. Whack-a-mole via a further byte-count bump is not the
right fix.

**Right fix:** WS-DEPS-MAJORS picky-krb 0.9 → 0.12 (returns `Err`
instead of panicking on malformed ct — behavior claimed in the
Dependabot bump commit body). If the upstream fix is real, restore the
retired `pac_parse_full` fuzz target at the same time.

**1.4.9 attempt (2026-09-01) — deferred, not risk-worth mid-cycle.**
Bumping to `picky-krb 0.12.4` locally triggered a public-API break:
`Authenticator` / `EncTicketPart` moved from struct-with-fields to
`ApplicationTag<Inner, N>` newtype form. All construction sites need
`X(XInner { .. })` instead of `X::from(XInner { .. })` and every
field access needs `.0.field`. Estimated 30+ mechanical edits in
`crates/kerberos/src/tgs.rs` alone, plus follow-on typing cascade
through `pac.rs` and consumers. Reverted to `0.9.6`; BUG-19 stays
mitigated by the existing `catch_unwind` guard around
`decrypt_ticket_pac` + `AES_MIN = 44` in the outer picky-krb call
sites. Targeted WS-DEPS-MAJORS session budgets the migration
alongside `picky-asn1-x509 0.13 → 0.15.4` and the RustCrypto
ecosystem bump (`md-5/md4/sha2 0.10 → 0.11`, `rc4 0.1 → 0.2`,
`rand 0.8 → 0.10`, `des 0.8 → 0.9`).

**Belt-and-braces:** WS-FUZZ-12 rebases every PAC-touching target on
top of `pac_parse_full` once it comes back, so residual generic-array
shapes get exercised end-to-end again.

## Workstreams (planned)

### WS-PROTOCOL-SECURITY — CLOSED in 1.4.9 (historical)

Every finding from the SEC-1 protocol/library review closed in 1.4.9
under commit `1fd4b80` (adhammer) + `bb57722` (windows-sddl sibling):

1. AH-001 / AH-002 — LDAP BER hardening (parent-bounded slices,
   indefinite/non-canonical/oversized rejection, 15/30 s deadlines,
   16 MiB message cap).
2. AH-003 — direct plaintext-LDAP-389 write refusal;
   `sasl_step1/sasl_step2` relay path preserved.
3. AH-004 / AH-005 — WinRM header/body/chunk/output budgets +
   `checked_add` framing arithmetic + 60 s HTTP read deadline.
4. AH-006 — `SecretString` / `SecretBytes` `ZeroizeOnDrop` types at
   every CLI ingress; guided-mode argv uses `env:VAR` indirection
   so the child spawn never carries a literal password.
5. AH-007 — write-DACL `validate_acl_bytes` refuses `AclSize < 8`,
   `AceSize < 4`, cross-boundary ACEs and mismatched counts.
6. WS-001 / WS-002 — `windows-sddl 0.1.3` models `DaclKind::{Null,
   NotPresent, Present}` and validates ACL/ACE bounds.

Live-validation receipts: `docs/receipts/1.4.9__2025.md` (3 pass on
SMB path, LDAP verbs error cleanly under 2025 channel-binding
hardening), `docs/receipts/1.4.9__2022.md` (1 pass, rest error
cleanly against non-routable-NIC config). Both approved.
2019 receipt owed — moved to `WS-WINDOWS-MATRIX-CI` below.

**Nothing further planned here in 1.5.0.** If a follow-up review
surfaces new findings against the 1.4.9 tree, they get their own
`SEC-N` workstream.

### WS-DEPS-MAJORS — take the Dependabot semver-major bumps (highest priority)

Dependabot generated 15 PRs on 2026-08-31 as its first sweep. Ten cargo
bumps + five GitHub-Actions bumps. The picky-krb bump is the
single highest-EV lift in the whole plan.

**picky-krb 0.9.6 → 0.12.4 (BUG-19 killer).**

- Verified 2026-09-01 during 1.4.9 that the naive `[workspace.dependencies]
  picky-krb = "0.12"` bump compiles clean at the resolver layer and
  breaks at the *use* layer: `Authenticator`, `EncTicketPart` and
  their siblings moved from struct-with-fields to
  `ApplicationTag<XInner, N>` newtype form.
- Mechanical fix pattern for every construction site
  (`crates/kerberos/src/tgs.rs` lines 501, 716, 774, 840, 1157–1185):
  ```rust
  // before (0.9):
  Authenticator::from(AuthenticatorInner { authenticator_bno: ..., .. })
  // after (0.12):
  Authenticator(AuthenticatorInner { authenticator_bno: ..., .. })
  ```
  And for every field access (`etp.auth_time` → `etp.0.auth_time`).
- Follow-on cascade to audit before declaring done: `crates/kerberos/
  src/pac.rs` (uses the same `EncTicketPart` fields via
  `decrypt_ticket_pac`), `crates/kerberos/src/unpac.rs` (PAC field
  access), `crates/secrets/src/pac*.rs` (any consumer of the same
  ASN.1 structs).
- Once compiled: retire the `catch_unwind` guard around
  `decrypt_ticket_pac`, drop the `AES_MIN = 44` / `RC4_MIN = 40`
  outer-bound workarounds, restore the retired `pac_parse_full`
  fuzz target, run the full corpus for 3 consecutive nightly runs
  before removing the mitigation notes from `docs/PLAN_1.4.9.md`.

**Other semver-major cargo bumps** (each its own dedicated commit,
each landed only if CI stays green — fmt/clippy/test/deny/
package-check/ledger + fuzz-non-regression):
- `md-5 0.10 → 0.11`, `md4 0.10 → 0.11`, `sha2 0.10 → 0.11`, `rc4 0.1
  → 0.2`, `rand 0.8 → 0.10`, `des 0.8 → 0.9` — RustCrypto ecosystem
  bump. Coordinated; move all together in one commit.
- `picky-asn1-x509 0.13 → 0.15.4` — coupled with the picky-krb bump;
  land in the same commit.
- `petgraph 0.6 → 0.8` — API breakage likely in `crates/graph`
  Tier-0 walker; the walker is well-covered by unit tests.
- `dialoguer 0.11 → 0.12` — TUI-only surface; verify interactive
  session prompts on Kali VBox per the hard rule.

Action: cherry-merge each PR that keeps CI green. Close breakers with
a one-line note explaining what would need to change.

### WS-PHASE2 — remove `rsa 0.9` advisory ignore

- Inventory every RSA operation in ADhammer + ms-icpr + adhammer-
  kerberos-via-pkinit.
- Fork `ms-icpr` in-tree as `crates/ms-icpr` + `[patch.crates-io]`.
- Replace `rsa 0.9` with `aws-lc-rs` RSA API. Wrapper LOC on top of the
  FFI shape.
- Remove `RUSTSEC-2023-0071` from `.cargo/audit.toml` and `deny.toml`.
- Update `SECURITY.md` — delete the "Marvin sidechannel accepted" note.

Verification: `cargo tree -i rsa --locked` returns nothing; `cargo
audit` passes with zero ignores.

### WS-CLI-SHRINK — move orchestration into `adhammer-sdk`

Move about 5,000 LOC from `cli/` into the SDK crate so a downstream
library consumer can compose without the binary. Target:
- `attacks/scan.rs` orchestration → `lib::scan()`
- `attacks/auto.rs` composite chain → `lib::auto()`
- `interactive.rs` state machine → `lib::interactive::Session`
- `ui::StageChecklist` → `lib::ui`
CLI stays as an argument parser + I/O wrapper.

Deliverable: one end-to-end lib-only example under `examples/` that
runs a scan without invoking the binary.

### WS-WINDOWS-MATRIX-CI — 2019 + 2022 + 2025 in the release gate

Elevated in 1.5.0 because 1.4.9 shipped with 2 of 3 Windows-version
receipts (2025 partial, 2022 partial, 2019 not booted).

Immediate operator work (before 1.5.0-alpha.1):
- **2019 VM**: no reachable IP in memory as of 2026-09-01 (stale
  `172.20.118.200` no longer responds). Boot the VM, capture the
  current IP + confirm AD services listen on a host-routable NIC,
  record IP + creds in `project_testlab_creds.md`, run
  `scripts/live_validation.sh` and commit the receipt.
- **2022 VM (2026-08-21 rebuild)**: the bridged-LAN NIC responds to
  ICMP but 445/88/389/636/5985 are filtered on that NIC because AD
  services bind only to the mshome interface, which isn't routable
  from the current host. Either re-attach the VM to a routable
  vSwitch or add a static route so the mshome subnet is reachable
  from the ADhammer host; then re-run the validator against the
  mshome IP for full-verb coverage. See `project_testlab_creds.md`
  in the private memory store for current IPs + creds.
- **2025 VM**: LDAP verbs still fail-cleanly under 2025 default
  channel-binding hardening. Long-term fix belongs in a new
  workstream `WS-LDAPS-CB` that speaks LDAPS with channel-binding
  tokens; deferred to 1.5.1.

CI workflow (self-hosted or `workflow_dispatch`):
1. Boots each VM from a clean snapshot.
2. Runs `scripts/live_validation.sh` against each with per-VM creds
   loaded from GitHub encrypted secrets.
3. Uploads the scrubbed receipt to `docs/receipts/<version>__<label>.md`.
4. Rolls back the snapshot.
5. Blocks the release tag until three fresh green receipts land.

### WS-NTDS-OFFLINE — the last-standing 1.4.8 deferral

Requires sibling `ese-parser` v0.2 to ship (B-tree walk + catalog +
row decode + long-value reassembly). Then `attack ntds-offline` verb
lands as the last 1.4.8-plan capability.

### WS-FUZZ-12 — extend fuzz surface to every parser

Add targets for:
- `pkinit_as_rep` — hostile AS-REP decode (via a stub that constructs
  from bytes without needing a real KDC round-trip)
- `ldap_entry` — `adhammer_collector::to_object` under random
  `SearchEntry`-shaped input
- `ntlmssp_type3` — hostile NTLMSSP Type3 parse
- `ntds_offline` — after ese-parser v0.2 lands
- `dpapi_ng` — LAPS-v2 GKDI envelope parse
- Re-add `pac_parse_full` if picky-krb 0.12 shipped a fix for the AES-CTS
  panic surface

### WS-BLOB-BYTE-ORACLE — impacket-oracle KAT for DPAPI blob

Complete WS-DPAPI-BLOB-ORACLE from 1.4.9. Run
`docs/synthetic_kat_blob.py` on Kali against impacket 0.14; embed the
expected ciphertext constants in `dpapi-offline masterkey::tests`
alongside the existing roundtrip test.

### WS-ZEROIZE-MIGRATE — actually migrate byte-Redacted sites

1.4.9 added `SecretBytes` + `Redacted<SecretBytes>::new_zeroize`.
1.5.0 migrates the audit-flagged sites:
- `adhammer_kerberos::pkinit::PkinitTgt` (`ccache`, `session_key`)
- `adhammer_kerberos::Tgt` (session key)
- `adhammer_cli::session` DPAPI seal buffers
- DPAPI master-key output holder in `attack dpapi-master-key`

Deprecate `Redacted::<Vec<u8>>::new` for byte material at the same
time.

### WS-EVIDENCE-BUNDLE — one signed bundle per release

Consolidate SBOM + sha256 sidecars + sigstore attestations + validation
receipts + fuzz-run summaries into one signed evidence bundle
(`adhammer_<version>_evidence.tar.zst.sig`). Emitted by
`release.yml` alongside binaries.

### WS-NDR64 — support Server 2025's optimal RPC path

Multi-crate. Extend `ms-ndr` sibling to encode/decode NDR64.
`dcerpc` sibling gains NDR64 transfer syntax option in bind
negotiation. Consumers opt in.

### WS-STABILITY-1-0 — cut 1.0 on the bottom-of-stack sibling crates

Per `docs/STABILITY.md` tier-1: `windows-sddl`, `ad-acl`, `ccache-io`,
`win32-min`. All stable enough. Semver-1.0 signals downstream
consumers to pin.

## Non-goals for 1.5.0

- Azure / Entra ID / M365 anything. Permanent no.
- Persistence framework (Skeleton-Key etc.). Same rule.
- GUI. Interactive TUI is the operator-in-the-loop story.
- Formal external audit — that's separate operator work, budgeted per
  the "external validation" line in the audit report.

## Ship gate (target)

- `cargo audit` — 0 vulnerabilities, 0 ignores (after WS-PHASE2).
- `cargo deny check` — 0 warnings, 0 skips (after Dependabot triage
  resolves duplicate-versions).
- `cargo package -p X --allow-dirty` — green on every crate.
- Ledger green + at least one green receipt for each of 2019 / 2022 /
  2025 in `docs/receipts/`.
- Fuzz job green for 3 consecutive runs (no discovered inputs cause
  panics after WS-FUZZ-12 landings).
- Every VALIDATION.md row that says "Windows: 2019 + 2022 receipt"
  moves to "Windows: 2019, 2022, 2025".

## Release cadence

- 1.5.0-alpha.1 tag when WS-DEPS-MAJORS + WS-PHASE2 + WS-CLI-SHRINK
  are green.
- 1.5.0-beta.1 when WS-WINDOWS-MATRIX-CI is producing receipts.
- 1.5.0 when all ship-gate criteria green + operator approves
  cascade-publish.
