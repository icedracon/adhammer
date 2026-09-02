# ADhammer 1.5.0 — comprehensive vector + lib + 100/100 analysis

Written 2026-09-02 in response to operator directive: "think about
1.5.0, all vectors, plans, 100/100, and libs needed."

Ground truth this document synthesizes:
- `ADHAMMER_BLACKBOX_RESEARCH.md` (2026-09-01) — top-30 tool landscape
  + honest ★★☆☆☆ baseline + 14 workstreams to reach ★★★★★.
- `ADHAMMER_SECURITY_REVIEW_CHECKPOINT_2026-09-01.md` — 8 preserved
  Codex candidates + sibling-source observations.
- Current `docs/PLAN_1.5.0.md` on `main` (post my-review-force-reset,
  no additions retained).
- Live sibling-crate inventory across 40+ local repos.

**All-local rule intact.** Nothing in this document commits to a
crates.io publish or a `git push`. Local commits only.

## Part 1 — the score model needs to change

Previous framing (`docs/PLAN_1.5.0.md`): 95/100 self-reachable ceiling,
final 5 points require external audit + 6-month track record + red-team.

That framing was correct WHEN the feature scope was frozen at 1.4.9's
authed-heavy tree. It stops being correct after 2026-09-01 research.
Operator's own top-30 rates 1.4.9 as **#30 with ★★☆☆☆** because the
tool assumes you already have creds. The 95/100 ceiling was measuring
the wrong thing.

**Revised score model — 4 axes.**

| Axis | Weight | 1.4.9 | Path to 25/25 |
|---|---|---|---|
| Correctness + supply chain (audit + fuzz + deny + SBOM + signed evidence) | 25 | 20 | close WS-ADVISORY-CLEANUP + WS-FUZZ-DEEP + WS-EVIDENCE-BUNDLE + external audit (final 3 external, self-reachable ~22/25) |
| Protocol coverage (black-box vector matrix — no-cred flow) | 25 | 6 | close WS-BB-* + WS-COERCER + WS-NOPAC + WS-MITM6 (self-reachable ~23/25) |
| Post-cred vector coverage (authed) | 25 | 22 | close WS-NTDS-OFFLINE + WS-LDAPS-CB + WS-DEPS-MAJORS (self-reachable ~24/25) |
| Ecosystem / stability / operator UX (SDK, docs, receipts, MSRV, interactive TUI) | 25 | 17 | WS-CLI-SHRINK + WS-STABILITY-1-0 + WS-MSRV-POLICY + WS-RECEIPT-SCHEMA + 6-month track record (self-reachable ~22/25) |
| **Total** | **100** | **65** | **~91 self-reachable; final 9 external** |

Honest current position: **65/100**, not 78/100 as I claimed in-session
yesterday. The 78 was flattering because it weighted authed-only vectors.

Realistic 1.5.0 target with focused scope: **80/100** (+15 delta;
mostly from Axis 2 + Axis 3 pushes).

## Part 2 — full vector matrix + sibling-lib map

Every 1.5.0-candidate verb + which sibling crate(s) it uses. Legend:
✓ = sibling exists local, ✗ = new work needed, ⚠ = exists but needs
bump/feature.

### 2.1 — Black-box discovery (Phase 0, no creds)

| Verb (proposed) | Displaces | Sibling deps | New LOC est. |
|---|---|---|---|
| `enum dns` | dig / dnsrecon | ✗ hand-roll SRV+A+PTR resolver (~200 LOC, no hickory) OR ⚠ `hickory-resolver` (300 KB dep) | 200 |
| `enum recon --range` | nmap NSE / rustscan | ✗ TCP fingerprint + banner grab + top-N ports (existing `enum net` extended) | 500 |
| `enum shares --anon` | smbclient / smbmap | ✓ `smb2-client 0.2.1` (has NullSession); needs SYSVOL walker + `Groups.xml` GPP-cpassword parser (100 LOC on top) | 300 |
| `enum rpc --null` | rpcclient (samba) | ✓ `dcerpc 0.2.8` + ✓ `ms-lsat 0.1.0` + ✓ `ms-scmr 0.1.0` + ⚠ needs `ms-srvsvc` (NEW sibling — 400 LOC) | 400 |
| `enum ldap --anon` | ldapsearch / windapsearch | ⚠ `ldap3-ntlmssp 0.12.1` has anon bind, RootDSE probe needs verb wrapper (~150 LOC) | 150 |
| `enum web --fingerprint` | WhatWeb / httpx | ✗ pure `reqwest` + regex (150 LOC, zero new deps) | 150 |
| `enum snmp` | onesixtyone / snmpwalk | ✗ NEW sibling `snmp-lite` (BER + community-string probe + top-100 OIDs, ~600 LOC) | 600 |
| `enum nullbind` | enum4linux-ng | ✓ `smb2-client` + ✓ `ms-lsat` + ✓ `dcerpc` + ⚠ needs `ms-samr` (NEW sibling — 800 LOC, SAM RPC verbs) | 800 |

**Sub-total new LOC**: ~3,100 workspace + ~1,400 sibling (2 new siblings: `snmp-lite`, `ms-samr`; optionally `ms-srvsvc`).

### 2.2 — Coerce + relay (partial gaps)

| Verb | Displaces | Sibling deps |
|---|---|---|
| `attack coerce --scan-all` | Coercer | ✓ `ms-coerce 0.1.0` (has vector table); add scan-all mode (~100 LOC) |
| `poison dhcpv6` | mitm6 | ✗ NEW work: raw-socket DHCPv6 responder (~600 LOC) + WPAD proxy (~200 LOC). Needs `pnet` OR hand-roll AF_PACKET on Linux + WSA_RAW on Windows |
| `attack relay --http-adcs-esc8` | ntlmrelayx.py | ✓ `ntlm-relay 0.2.0` + ✓ `ms-icpr 0.1.2` — verify chain works end-to-end |

### 2.3 — Kerberos (well-covered; only picky-krb bug-fix pending)

| Verb | Sibling deps |
|---|---|
| Existing 18/20 vectors | ✓ Full picky-krb + `ccache-io 0.1.0` + `ms-pac 0.1.0` + `ms-pac-forge 0.2.0` + `ms-kile-fast 0.1.0` + `ms-pkca 0.1.0` |
| Picky-krb 0.9 → 0.12 (WS-DEPS-MAJORS) | Migration path documented in `PLAN_1.5.0.md` §BUG-19; 30+ mechanical edits |
| `attack nopac` | ✓ `ms-drsr 0.2.0` + samAccountName mutation via existing LDAP write path |

### 2.4 — ADCS (well-covered)

| Verb | Sibling deps |
|---|---|
| Existing ESC1-15 + ESC8 | ✓ `ms-icpr 0.1.2` + ✓ `ms-crtd 0.1.0` + ✓ `ms-xcep 0.1.0` |
| — | — |

### 2.5 — Post-cred exploitation (mostly there)

| Verb | Sibling deps | Gap |
|---|---|---|
| DCSync | ✓ `ms-drsr 0.2.0` | — |
| Golden / Silver | ✓ `ms-pac-forge 0.2.0` | — |
| Shadow-cred | ✓ `ms-pkca 0.1.0` + ✓ `dpapi-ng 0.2.0` | — |
| LSASS / Skeleton | ✗ | Permanent NO (see 1.5.0 non-goals) |
| DPAPI master-key harvest | ✓ `dpapi-offline 0.1.2` | Same-cycle done, KAT-oracle deferred to WS-BLOB-BYTE-ORACLE |
| Registry hive parse | ✓ (in adhammer directly) | — |
| NTDS.dit offline | ⚠ needs `ese-parser 0.2` (B-tree walk + catalog) | WS-NTDS-OFFLINE deferred |
| GKDI LAPS-v2 unwrap | ✓ `ms-gkdi 0.1.0` + ✓ `dpapi-ng 0.2.0` | — |
| BackuprKey | ✓ `ms-bkrp 0.1.1` (live-validated) | — |
| Trust discovery | ✓ `ms-lsad 0.1.0` (live-validated) | — |
| Eventlog native read | ✓ `windows-eventlog-native 0.2.2` | Windows-runner only |
| WMI COM | ✓ `windows-wmi-com 0.1.0` + ✓ `ms-wmi 0.1.0` + ✓ `ms-dcom 0.1.0` | — |
| MS-TDS (MSSQL auth chain) | ✓ `ms-tds 0.1.1` | — |
| Netlogon (nrpc / Zerologon) | ✓ `ms-nrpc 0.1.0` (live-validated) | — |

### 2.6 — External deps for cracking hand-off

| Cap | Deps |
|---|---|
| hashcat command emit | External (no spawn); read the hash format, emit correct `-m` mode + rule |
| hash type ident | ⚠ Add `hashglass 0.1.0` from GitHub (user's own crate); ONE new dep |

## Part 3 — realistic 1.5.0 scope (8 workstreams, ~4 weeks)

Aim: +15 score points (65 → 80). Any more scope is 1.5.1.

**Priority order = ROI-descending**:

### WS-1 (P0): WS-BB-FOUNDATION — DNS + ANONLDAP + WEBFP
Combined into one workstream because they share ~zero code and are all
1-2 days each. Bootstraps the black-box mode's Phase 0.
- `enum dns --domain <realm>` (SRV + A + PTR + zone-transfer probe)
- `enum ldap --anon` (RootDSE + `defaultNamingContext` walk)
- `enum web --fingerprint` (WhatWeb-shape endpoint regex)
**Effort**: 5-6 days. **Score delta**: +3 (Axis 2 jump from 6→9).

### WS-2 (P0): WS-LDAPS-CB
RFC 5929 channel-binding tokens in `crates/ldap`. Without this, the
"10/10 verb pass per DC" ship-gate is unreachable — every 1.4.9
receipt shows `data 52e` on LDAP verbs.
**Effort**: 3-4 days. **Score delta**: +2 (Axis 3 22→24; also
required for the receipt-based ship-gate).

### WS-3 (P0): WS-DEPS-MAJORS (picky-krb 0.9 → 0.12 + RustCrypto 0.11)
Retires BUG-19 mitigation + closes generic-array panic class + allows
`pac_parse_full` fuzz target restoration.
**Effort**: 3-4 days (mechanical + fuzz-verify).
**Score delta**: +2 (Axis 1: 20→22; also unblocks WS-FUZZ-12).

### WS-4 (P1): WS-BB-NULLBIND + WS-BB-RPCNULL
Combined. Both need SAMR + LSAT null-session RPC. Requires NEW sibling
`ms-samr 0.1.0` (~800 LOC) or add SAMR verbs to existing `ms-lsad`
(cleaner — LSAT and SAMR are related MS-* families).
- `enum nullbind --host <dc>` (enum4linux-ng shape)
- `enum rpc --null` (rpcclient shape)
**Effort**: 6-8 days (mostly `ms-samr` sibling work).
**Score delta**: +3 (Axis 2 9→12).

### WS-5 (P1): WS-BB-SHARES
`enum shares --anon` + SYSVOL walker + GPP-cpassword harvest. Uses
existing `smb2-client 0.2.1`; only 300 LOC on top.
**Effort**: 3 days. **Score delta**: +2 (Axis 2 12→14).

### WS-6 (P1): WS-RECEIPT-SCHEMA + WS-CASCADE-REHEARSAL
Combined infra pair. Together they unblock safe cascade-publish + CI
enforced receipt validation.
- `docs/receipts/SCHEMA.md` + `scripts/validate_receipt.py` + CI job
- `scripts/cascade_dry_run.sh` + `docs/CASCADE_1.5.0.md` (auto-gen)
**Effort**: 3-4 days. **Score delta**: +2 (Axis 1: 22→24 via
evidence-integrity + Axis 4: 17→18).

### WS-7 (P2): WS-CLI-SHRINK
Move ~5000 LOC from `cli/` into `adhammer-sdk`. Unlocks downstream
library composition without the binary.
**Effort**: 5-6 days. **Score delta**: +1 (Axis 4 18→19).

### WS-8 (P2): WS-FUZZ-DEEP + WS-FUZZ-12 (extension only)
Nightly 30-min-per-target + coverage-guided + seeded corpora +
add `pkinit_as_rep` + `ldap_entry` + `dpapi_ng` targets.
**Effort**: 3-4 days (workflow + seed corpus curation).
**Score delta**: +1 (Axis 1 22→23).

**Total scope**: ~30-35 days single-operator. Realistic 5-week sprint.
**Ship gate score**: 65 + 15 = **80/100**.

## Part 4 — deferred to 1.5.1 / 1.5.2 / 1.6.0

### 1.5.1 candidates (next-highest ROI)
- WS-BB-BLACKBOX — one-command orchestrator (needs WS-1..5 landed
  first as building blocks)
- WS-COERCER — unified coerce scan mode (small; folds into 1.5.1
  because it depends on the coerce-scan output format WS-BB-BLACKBOX
  will consume)
- WS-ADVISORY-CLEANUP — rsa 0.9 → aws-lc-rs; ADR-2
- WS-NOPAC — CVE-2021-42278/42287
- WS-HASHGLASS — dep

### 1.5.2 candidates
- WS-BB-SNMP — needs NEW `snmp-lite` sibling (600 LOC)
- WS-BB-RECON — ARP L2 + TCP fingerprint at scale
- WS-MITM6 — DHCPv6 WPAD relay chain (needs raw-socket sibling)
- WS-NTDS-OFFLINE — depends on `ese-parser 0.2` shipping externally
- WS-EVIDENCE-BUNDLE — signed one-bundle-per-release

### 1.6.0 (major)
- WS-NDR64 — Server 2025 optimal RPC path
- WS-STABILITY-1-0 — cut 1.0 on tier-1 siblings (windows-sddl,
  ad-acl, ccache-io, win32-min)
- WS-ZEROIZE-MIGRATE — sweep all byte-Redacted sites to SecretBytes

## Part 5 — sibling libs needed (concrete)

**Already exist locally, ready for 1.5.0**:
- `dcerpc 0.2.8`, `dpapi-ng 0.2.0`, `dpapi-offline 0.1.2`
- `ms-icpr 0.1.2`, `ms-pac 0.1.0`, `ms-pac-forge 0.2.0`, `ms-lsad 0.1.0`, `ms-lsat 0.1.0`
- `ms-dcom 0.1.0`, `ms-wmi 0.1.0`, `ms-bkrp 0.1.1`, `ms-crtd 0.1.0`, `ms-csra 0.1.2`
- `ms-dnsp 0.1.0`, `ms-even6 0.1.0`, `ms-gkdi 0.1.0`, `ms-tds 0.1.1`, `ms-xcep 0.1.0`
- `ms-ndr 0.1.3`, `ms-drsr 0.2.0`, `ms-nrpc 0.1.0`, `ms-tsch 0.1.0`, `ms-scmr 0.1.0`
- `ms-pkca 0.1.0`, `ms-kile-fast 0.1.0`, `ms-coerce 0.1.0`, `ms-rodc 0.1.0`
- `windows-sddl 0.1.3`, `ad-acl 0.1.0`, `win32-min 0.1.3`, `ccache-io 0.1.0`
- `windows-lsa 0.2.1`, `windows-scm 0.2.1`, `windows-token 0.2.1`
- `windows-eventlog-native 0.2.2`, `windows-sspi-shim 0.1.0`, `windows-wmi-com 0.1.0`
- `ldap3-ntlmssp 0.12.1`, `ntlmssp` (in adhammer), `ntlm-relay 0.2.0`, `smb2-client 0.2.1`

**NEW siblings needed for 1.5.0 scope (WS-4)**:
1. **`ms-samr 0.1.0`** — SAMR RPC verbs for null-session enum
   (enumdomusers, enumdomgroups, lookupsid, RID-cycle). ~800 LOC.
   Sits alongside `ms-lsad 0.1.0`.

**NEW siblings for 1.5.1 (deferred)**:
2. **`ms-srvsvc 0.1.0`** — server service RPC (NetShareEnumAll etc.) — 400 LOC. May fold into `smb2-client` extension instead.

**NEW siblings for 1.5.2 (deferred)**:
3. **`snmp-lite 0.1.0`** — SNMPv1/v2c community probe + top-100 OIDs. ~600 LOC.
4. **`dhcp6-server 0.1.0`** — DHCPv6 raw-socket responder (for WS-MITM6). ~600 LOC.

**Bumps required in 1.5.0**:
- `picky-krb 0.9 → 0.12` (WS-DEPS-MAJORS; 30+ mechanical edits)
- `picky-asn1-x509 0.13 → 0.15.4` (coupled)
- RustCrypto ecosystem: `md-5 0.11`, `md4 0.11`, `sha2 0.11`, `rc4 0.2`, `rand 0.10`, `des 0.9`
- `petgraph 0.6 → 0.8` (tier-0 walker; well tested)
- `dialoguer 0.11 → 0.12` (TUI; verify on Kali VBox)

## Part 6 — path to 100/100

Self-reachable ceiling stays at ~91/100 with the revised 4-axis model.
Final 9 points require:

| Missing 9 pts | What it needs |
|---|---|
| **+3** External security audit | Paid engagement (Trail of Bits / NCC Group / Doyensec class). Scope: kerberos + LDAP + SDDL + SMB paths. Est. $30-60k, 4-8 weeks. Not 1.5.0. |
| **+3** 6-month post-release track record | Calendar time. 1.5.0 ships → 6 months of zero-CVE in `adhammer-*` crates → +3. Cannot be shortcut. |
| **+3** Independent red-team attestation | An outside red-team runs a full engagement using ADhammer as their primary tool + writes a public attestation of what did/didn't work. Community trust signal. Requires operator outreach. |

Alternative to formal audit (cheaper, faster, weaker signal):
- Public bug bounty on adhammer sibling crates (crowd-sourced audit)
- CI-published fuzz coverage numbers (measurable, not just "we fuzz")
- Reproducible-build attestations (already scaffolded in
  `docs/REPRODUCIBLE_BUILDS.md`; needs one green attestation to count)

## Part 7 — decisions the operator needs to make

Blocking questions for the actual 1.5.0 plan:

**Q1**: Confirm scope split — 8 workstreams (~5 weeks) for 1.5.0, or
push more workstreams in and stretch to ~8 weeks?

**Q2**: `ms-samr` — new sibling crate (cleaner, ~800 LOC) OR fold SAMR
verbs into existing `ms-lsad` (both are LSA-adjacent RPC)? My default:
new sibling to keep LSAD focused on LSA/trusted-domain enum.

**Q3**: DNS resolver — hand-roll ~200 LOC per hand-rolling preference
(matches windows-sddl / ccache-io pattern) OR pull `hickory-resolver`
for time-to-ship (~300 KB, well-audited)? My default: hand-roll (aligns
with s-tier minimalism).

**Q4**: WS-CLI-SHRINK before or after black-box additions? Doing it
first means new verbs live in SDK from day one; doing it after means
larger single migration. My default: after WS-BB-FOUNDATION lands (the
cascade of new verbs is easier to migrate once).

**Q5**: 1.5.0 ship-policy — same LOCAL rule as 1.4.9, or restore
crates.io cascade after WS-CASCADE-REHEARSAL green? My default: LOCAL
until rehearsal green, then cascade in one wave with operator
approval.

**Q6**: Star-rating target — the research targets ★★★★★. Realistic
for 1.5.0 with 8 workstreams: ★★★ (from ★★). Reaching ★★★★★ requires
1.5.0 + 1.5.1 + 1.5.2 (black-box orchestrator + coercer scan-all +
mitm6 + noPac all landed). Confirm the release cadence maps to that.

## Appendix A — what's NOT in this plan (permanent no)

Same list as `PLAN_1.5.0.md` §Non-goals:
- Azure / Entra ID / M365. Permanent NO.
- Persistence framework (Skeleton-Key / SSP-inject / DSRM-hijack).
  Same rule (per `feedback-adhammer-hard-rules`).
- GUI. TUI is the operator-in-the-loop story.
- C2 features (per NO_C2 stance).
- AI features (WS-21/22 rejected).

## Appendix B — 1.4.9 outstanding bugs

Per `PLAN_1.5.0.md` §Bug-carry:
- **CI-1** — package-check under all-local. Mitigated via gate + manifest-sanity. Closes in 1.5.0 automatically when cascade rehearsal lands.
- **BUG-19** — picky-krb generic-array panic. Right fix is WS-DEPS-MAJORS (WS-3 above).

No other bugs found in 1.4.9 shakedown as of 2026-09-02.

## Appendix C — 8 Codex candidates from 2026-09-01 review

Six landed as SEC-1 remediation in 1.4.9 (AH-001..007 + WS-001/002).
Two preserved for validation:
- WinRM multipart signature-length arithmetic — recalibrated as 64-bit-only, not a P1 for us but track.
- WinRM credentials bypass `Redacted<T>` — no logging sink found; validate against explicit secret-storage policy. Bundle with WS-ZEROIZE-MIGRATE (1.6.0).

No new bug-carry from these.
