# ADhammer 1.5.0 — canonical plan

Written 2026-09-02. **Hardening carve-out:** the P0 bug-fix work
(BF-1..8, CI-FAIL-1/2, G-1) moved to a separate patch release —
see [`docs/PLAN_1.4.10.md`](PLAN_1.4.10.md). This document now
covers only genuine 1.5.0 capability work: new attack verbs,
dependency major bumps, advisory cleanup, CLI shrink into SDK,
receipt schema + cascade rehearsal, deep fuzz, MSRV policy, LDAPS-CB
investigation, DNS hand-roll, and the black-box orchestrator CLI.

Supersedes:
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

## Audit history (2026-09-02, all closed in 1.4.10)

The 2026-09-02 audit surfaced 8 behavioural findings (BF-1..8), 2 CI
failures (CI-FAIL-1/2) and 1 foundation-drift finding (G-1). Every
item landed in the 1.4.10 patch release — see
[`docs/PLAN_1.4.10.md`](PLAN_1.4.10.md) for the workstream-by-
workstream close notes. Original finding text preserved in the
1.4.10 plan; not duplicated here.

Post-1.4.10 baseline for 1.5.0 planning:
- `cargo test --workspace` green.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo build --workspace` at MSRV 1.88 green.
- `cargo fmt --all --check` green.
- Supported-feature-matrix job green ({no-default, default,
  tls-native only, mssql+gssapi, experimental-gkdi}).
- Offline `cargo audit` — one standing ignore (`RUSTSEC-2023-0071`,
  rsa 0.9.10 Marvin sidechannel; closes here in `WS-ADVISORY-CLEANUP`).
- BUG-19 (picky-krb generic-array panic) production-mitigated;
  fuzz still red — closes here in `WS-DEPS-MAJORS`.

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
| G-1..G-6 | 1.4.10 hardening | landed in 1.4.10; see [`docs/PLAN_1.4.10.md`](PLAN_1.4.10.md). Deferred call-site follow-ups (WS-SECRET-BOUNDARY-CALLSITES / WS-CLI-PLAINTEXT-LDAP-FLAG / WS-LDAP-INTEGRITY-RESPONSE-BYTES / WS-SECRET-BOUNDARY-WINDOWS-DACL / WS-CLI-GPP-DUMP-FLAG / direct-println wiring) fold into 1.5.0's WS-CLI-SHRINK | — | — | landed |
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

Priorities are release-gate-derived. The five hardening workstreams
that previously sat at P0 (WS-FEATURE-MATRIX, WS-OUTPUT-SANITIZE,
WS-SECRET-BOUNDARY, WS-LDAP-INTEGRITY, WS-FOUNDATION-INTEGRATE)
moved to 1.4.10 (see PLAN_1.4.10.md). 1.5.0's remaining priority
tier is P1 + P2 as originally categorized — no new P0 for this
release.

### Hardening workstreams — moved to 1.4.10 (see [`docs/PLAN_1.4.10.md`](PLAN_1.4.10.md))

The five P0 workstreams below landed 2026-09-02 as bug-fix / defence-
in-depth against 1.4.9's tree, not as new 1.5.0 capability. They now
live in the 1.4.10 patch-release plan. Named here so cross-references
from 1.5.0 workstreams below (WS-DEPS-MAJORS, WS-CLI-SHRINK etc.)
resolve:

| Workstream | Bug fixed | Landed at |
|---|---|---|
| WS-FEATURE-MATRIX | CI-FAIL-1 (audit misinterpretation) | 1.4.10 |
| WS-OUTPUT-SANITIZE | BF-8 (control-char sanitization) | 1.4.10 |
| WS-SECRET-BOUNDARY | BF-2 (GPP plaintext boundary) | 1.4.10 |
| WS-LDAP-INTEGRITY | BF-1, BF-7 (simple_bind + budgets) | 1.4.10 |
| WS-FOUNDATION-INTEGRATE | G-1, BF-3, BF-4, BF-5 (type foundation + gates) | 1.4.10 foundation, capability in 1.5.0 |

WS-FOUNDATION-INTEGRATE lands the type surface (`EngagementScope`,
`BlackBoxRunner`) in 1.4.10 as a patch-safe additive change; the
observable no-cred discovery capability the types support is a 1.5.0
addition (WS-FOUNDATION-DNS-HANDROLL + WS-FOUNDATION-BLACKBOX-CLI
below).

### WS-FOUNDATION-DNS-HANDROLL (landed 2026-09-03, all local)

The D2-locked hand-rolled DNS resolver — no `hickory-resolver`.
Landed in two slices:

1. `crates/collector/src/dns_wire.rs` — pure RFC 1035 message codec
   (`encode_query` + `parse_response`), zero I/O, name decompression
   with a bounded pointer budget. No-panic on hostile bytes (10 unit
   tests + `fuzz/fuzz_targets/dns_wire.rs`).
2. `crates/collector/src/discovery.rs` — rewritten off the untracked
   hickory draft onto `dns_wire` + tokio UDP/TCP. `HandRolledDnsLookup`
   (UDP → TCP-on-truncation, txn-id match); `DnsLookup` trait keeps the
   SRV-family walk + scope filter + PTR collection transport-agnostic.
   `discover_dns(scope, nameservers)` + `system_nameservers()`
   (unix resolv.conf). BF-3 `allows()` scope semantics wired at the
   discovery layer. `BlackBoxRunner::discover_dns` restored in the SDK
   as a Discovery-class gated check.

This closes the "foundation drift" — `discovery.rs` is now tracked +
compiled + tested (was an untracked non-compiling draft). Remaining
Windows nameserver auto-detection (adapter enumeration) folds into
`WS-FOUNDATION-BLACKBOX-CLI` when the `run` verb lands.

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
| `cargo fmt --all --check` green | required | ✓ post-1.4.10 (CI-FAIL-2 closed) |
| Supported-feature-matrix job green ({no-default, default, tls-native only, mssql+gssapi, experimental-gkdi}) | required | ✓ post-1.4.10 (CI-FAIL-1 reclassified) |
| `cargo audit` 0 vulnerabilities + 0 ignores | 8 | 0 (rsa 0.9 ignore) |
| `cargo deny check` 0 warnings + 0 skips | 4 | 0 (transitive dupes) |
| Fuzz job green 7 consecutive nights | 5 | 0 (BUG-19 outstanding) |
| Reproducible-build attestation green | 4 | 0 |
| Signed evidence bundle (SBOM + sigstore + receipts + fuzz summary) | 4 | 0 |
| Foundation integrated + policy-enforced tests | 5 | ✓ post-1.4.10 (WS-FOUNDATION-INTEGRATE landed) |
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

- **1.4.10** — hardening batch (see `docs/PLAN_1.4.10.md`) tagged
  and green locally before 1.5.0 branch opens.
- **1.5.0-alpha.1** — WS-DEPS-MAJORS + WS-ADVISORY-CLEANUP landed
  on top of 1.4.10; foundation types become observable via
  WS-FOUNDATION-BLACKBOX-CLI + WS-FOUNDATION-DNS-HANDROLL.
- **1.5.0-beta.1** — WS-DEPS-MAJORS + WS-ADVISORY-CLEANUP green;
  WS-FUZZ-DEEP running for 3 nights.
- **1.5.0-rc.1** — WS-CASCADE-REHEARSAL green on the rc commit;
  WS-RECEIPT-SCHEMA validator green; every P1 landed.
- **1.5.0** — every ship-gate row above ≥ target weight + operator
  approves cascade-publish.

## Bug-carry (append-only during shakedown)

### CI-FAIL-1 — `--all-features` breaks ldap3
**State:** closed 2026-09-02 in 1.4.10; see
[`docs/PLAN_1.4.10.md`](PLAN_1.4.10.md) §WS-FEATURE-MATRIX.

### CI-FAIL-2 — `cargo fmt --check` fails on live-test files
**State:** closed 2026-09-02 in 1.4.10; see
[`docs/PLAN_1.4.10.md`](PLAN_1.4.10.md) §CI-FAIL-2.

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
