# ADhammer 1.5.0 — hard plan (post-1.4.9-audit + capability push)

Written 2026-08-31 while 1.4.9 is still landing. Score target: **95/100
self-reachable ceiling.** The final 3 points (external audit + 6-month
track record + independent red-team attestation) stay explicitly out of
this plan.

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

## Workstreams (planned)

### WS-DEPS-MAJORS — take the Dependabot semver-major bumps

Dependabot generated 15 PRs on 2026-08-31 as its first sweep. Ten cargo
bumps + five GitHub-Actions bumps.

Cargo bumps that are semver-major:
- `picky-krb 0.9 → 0.12` — may retire the BUG-16/17/18 workaround (the
  AES-CTS-HMAC-SHA1 panic in generic-array). Highest-value bump. Would
  let us re-add the `pac_parse_full` fuzz target.
- `md-5 0.10 → 0.11`, `md4 0.10 → 0.11`, `sha2 0.10 → 0.11`, `rc4 0.1
  → 0.2`, `rand 0.8 → 0.10`, `des 0.8 → 0.9` — RustCrypto ecosystem
  bump. Coordinated; move all together.
- `picky-asn1-x509 0.13 → 0.15.4`, `petgraph 0.6 → 0.8` — API breakage
  possible.
- `dialoguer 0.11 → 0.12` — TUI-only surface.

Action: cherry-merge each PR that keeps CI green (fmt/clippy/test/deny/
package-check/ledger + fuzz-non-regression). Close breakers with a
one-line note explaining what would need to change.

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

The operator has 2019server + 2022server + 2025server1 running in
Hyper-V. Add a self-hosted (or manual) workflow that:

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
