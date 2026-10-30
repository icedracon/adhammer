# ADhammer 1.5.3 — HARD EXECUTION PLAN

**kerbcore swap (retire picky-krb) · PKINIT residual · 3 live-fire fixes · CI unblock**

Status: planning (execution-grade). Owner: icedracon. Date: 2026-09-20.
Baseline: **1.5.2 shipped** (crates.io 12/12 @ 1.5.2, tag `v1.5.2`@`7b5e60b`, main CI green@`f847b4f`).
MSRV 1.88. No push/publish authorized here; local builds only.
Coupling data: 2026-09-20 workspace map (file:line below are from it — re-grep before editing).

## Progress (2026-09-20) — all LOCAL, unpushed

- **P0.1 DONE.** kerbcore wired: `kerbcore = { path = "../kerbcore", version = "0.3" }` in the
  workspace + `crates/kerberos/Cargo.toml`. **kerbcore 0.3.0 is LOCAL-ONLY (crates.io max =
  0.2.1)** → path dep for dev; the ship sequence must publish kerbcore 0.3.0 to crates.io FIRST
  (bottom-up), then drop the path. `cargo check -p adhammer-kerberos` green — no aws-lc/ring
  clash (kerbcore pulls no TLS), shares the existing `aes 0.8.4`, MSRV 1.88 holds. No feature
  gate used (direct in-place migration; both picky + kerbcore present during the window).
- **K1 AS-REP sub-path DONE + LIVE-VALIDATED.** `build_as_req` (→ kerbcore-encoded `Vec<u8>`,
  IA5 validation preserved) + `kerbrute_probe` + `asrep_roast` migrated onto
  `kerbcore::client::build_as_req` + `messages::KdcRep/KrbError::decode`. Workspace clippy
  `-D warnings` clean · 466 tests/0 fail · fmt-clean · live-fire host→DC01 = **2 AS-REP hashes**
  (lowpre + asrep_seed, `-m 18200`) + 6 Kerberoast (picky path, untouched), 0 errors.
- **GOTCHA:** `cargo fmt --all` reaches the path-dep kerbcore and reformats its `examples/`+`src/`.
  Use scoped `cargo fmt -p adhammer-…` during the migration window (reverted the side-effect).
- **NEXT:** K1-TGS (`roast_spn`/`get_tgt` in `tgs.rs`) — needs `KerberosKey` crypto + s2k +
  `parse_etype_info2` salt + `build_tgs_req_with_options` + TGS-REP parse.

---

## 0. Contract & invariants (do not violate)

- **INV-1 · public API frozen.** `adhammer-kerberos`'s exported surface (see §2) stays
  byte-identical → 1.5.3 = **patch**. Any public signature/error-type change → stop, it's 1.6.0.
  Verify: `git show <candidate> -- crates/kerberos | grep -E '^-.*\bpub\b'` is empty.
- **INV-2 · picky-krb never bumped.** It is deleted, not upgraded. 0.9→0.12 is the reverted
  landmine. Zero `picky_krb::` / `picky_asn1_der::` / `picky_asn1::` imports remain in
  `crates/kerberos` at K-done (`picky-asn1-x509` is the ONE survivor — PKINIT only, §P).
- **INV-3 · no new default features, no `[patch.crates-io]`, MSRV stays 1.88.**
- **INV-4 · byte-diff before delete.** No picky code path is removed until its kerbcore
  replacement is proven byte-identical on a fixed wire fixture (§3 harness).
- **INV-5 · lab hygiene.** Live-fire output (DC01 hashes/keys/hosts) is terminal-only;
  redact per `[feedback_never_leak_lab_identifiers]` before any fixture is committed.

## 1. What changes vs what stays

| Retired in 1.5.3 | Survives (isolated) | Untouched |
|---|---|---|
| `picky-krb` 0.9 | `picky-asn1-x509` 0.14 → PKINIT/CSR CMS+X.509 only (`pkinit.rs`, `csr.rs`) | `ms-pac-forge` (PAC marshal) |
| `picky-asn1` 0.10 | (its picky-asn1/-der transitive, pulled by picky-asn1-x509) | `ms-crtd`, `ms-icpr`, `dcerpc`, all non-kerberos crates |
| `picky-asn1-der` 0.5 | — | RC4/NT-hash path (already on `ms-pac-forge`) |

Full picky retirement (kill picky-asn1-x509 too) = **1.6 item P-2** (needs a CMS/X.509
answer kerbcore does not provide). 1.5.3 does the picky-**krb** swap only. Say this plainly.

## 2. adhammer-kerberos public API (the frozen contract — INV-1)

Re-exported from `tgs` via `lib.rs:36-41`: `asktgt, build_ap_req_gss,
build_ap_req_gss_aes256, check_credential, forge_diamond_tgt, forge_golden_tgt,
forge_silver_tgt, get_service_ticket, get_tgt, get_tgt_by_hash, golden_ccache,
overpass_the_hash, rbcd_impersonate, rbcd_impersonate_by_hash, roast_spn, silver_ccache,
silver_service_ticket, CredResult, ServiceTicket, Tgt, TicketTimestamps`.
Top-level: `ETYPE_RC4_HMAC/AES256/AES128`, `Candidate`, `candidates`, `kerbrute_probe`,
`KerbruteOutcome`, `name_asrep_krb_error`, `format_asrep{,_aes}`, `format_tgs{,_aes}`.
Modules: `csr`, `gss`, `pac`, `pkinit`, `rc4`, `shadowcred`, `unpac`.
Callers (must keep compiling unchanged): `crates/sdk/src/lib.rs:30`; `cli/src/attacks/{roast,asktgt,golden,silver,diamond,ptt,rbcd,abuse,esc1,icpr_esc1,kerb,relay,shadowcred,spray,unpac}.rs`; `cli/src/enums/krb.rs`; `fuzz/fuzz_targets/pac_credential_info.rs`.

## 3. picky → kerbcore symbol map (the whole migration on one screen)

kerbcore 0.3.0 @ `C:\Users\zevs\Documents\kerbcore`. Codec is `.encode()/.decode()` +
free fns — **not** `to_vec/from_bytes::<T>`, so each of ~50 sites is a rewrite.

| Concern (picky today) | picky site(s) | kerbcore replacement |
|---|---|---|
| AS-REQ build | `lib.rs:118-161` | `client::build_as_req` |
| AS-REP / KRB-ERROR parse | `lib.rs:341-375` | `messages::{KdcRep,KrbError}` + `client::parse_enc_kdc_rep_part` |
| TGS-REQ / AP-REQ / authenticator | `tgs.rs:562-623` | `client::build_tgs_req_with_options`, `build_ap_req_with_confounder` |
| TGS-REP parse + ticket enc-part carve | `tgs.rs:620-639` | `messages::KdcRep` → `.ticket.enc_part` |
| etype 17/18 AES-SHA1 crypto | `tgs.rs:69,86-98,245,272,334,360,516,1279,1585` | `keys::KerberosKey::{encrypt,decrypt}` / `crypto::*` |
| etype 19/20 AES-SHA2 | *(picky lacks)* | `rfc8009` — **net-new coverage** |
| etype 23 RC4 | `rc4.rs` (already ms-pac-forge) | `kerbcore::rc4` (consolidate or keep ms-pac-forge) |
| string-to-key | `tgs.rs:235,324,509,1587` | `KerberosKey::string_to_key` / `crypto::string_to_key` / `rfc8009::string_to_key` |
| ETYPE-INFO2 salt/iters | picky `EtypeInfo2` | `client::parse_etype_info2` → `EtypeInfo2Entry::s2k_iterations` |
| checksum (S4U PA-FOR-USER) | `tgs.rs:993-995` | `KerberosKey::checksum` / `crypto::hmac_sha1_96` |
| DER encode/decode (~50) | `lib.rs/tgs.rs/pkinit.rs` `picky_asn1_der::{to_vec,from_bytes}` | `der` + `types` (`.encode()/.decode()`) |
| EncTicketPart decrypt | `pac.rs:29`, `unpac.rs:271-287` | `acceptor::{parse_enc_ticket_part,decrypt_ticket,EncTicketPart}` (ships in 0.3) |
| GSS AP-REP / SPNEGO | `gss.rs` | `gss` (RFC 4121) + `spnego` (richer than ours) |
| **PKINIT CMS/X.509 + CSR** | `pkinit.rs:52-54`, `csr.rs` | **NONE** → stays on picky-asn1-x509 (§P) |
| Golden/Silver/Diamond forge | `tgs.rs` EncTicketPart encode+encrypt | **NONE** → re-express on kerbcore `der`+`crypto` (K-3) |

---

## PHASE PLAN (task IDs, files, effort, gate, rollback)

Critical path = **P0 → K1 → K2 → K4 → K3 → P1 → K9**. X-track and C-track run parallel.

### P0 · Prep + byte-diff harness — 0.5d — *gate for everything*

- **T0.1** Add `kerbcore = "0.3"` to `[workspace.dependencies]` + `crates/kerberos/Cargo.toml`;
  add `[features] kerbcore = ["dep:kerbcore"]` (dev-time gate). Confirm `cargo tree` shows no
  aws-lc/ring provider clash, MSRV 1.88 holds, `Cargo.lock` resolves.
- **T0.2** Capture golden wire fixtures from DC01 (redacted): AS-REP (etype 18 + 23),
  TGS-REP (18 + 23), KRB-ERROR (preauth-required, etype-nosupp). Store in
  `crates/kerberos/tests/fixtures/` (scrub realm/host/hashes → placeholders).
- **T0.3** Harness `tests/kerbcore_bytediff.rs`: feed each fixture through the picky path and
  the kerbcore path, assert identical parsed fields + identical re-encoded bytes.
- **GATE-0:** harness compiles, both paths run, fixtures load. **Rollback:** drop the feature; picky untouched.

### K1 · roast beachhead — 2d — *proves codec+crypto swap on the hottest path*

- **T1.1** `build_as_req` (`lib.rs:118-161`) → `client::build_as_req`; field-by-field map.
- **T1.2** `asrep_roast` (`lib.rs:340-383`): `to_vec`/`from_bytes::<AsRep>` → kerbcore encode/
  `parse_enc_kdc_rep_part`; enc-part source `enc.etype.0.0`/`enc.cipher.0.0` → KdcRep fields.
- **T1.3** `get_tgt` session-key decrypt (`tgs.rs`) → `KerberosKey::decrypt`.
- **T1.4** `roast_spn` (`tgs.rs:548-640`): authenticator build+seal → TgsReq → TgsRep parse →
  ticket enc-part carve. **Keep `format_{asrep,tgs}{,_aes}` (`lib.rs:391-446`) verbatim.**
- **GATE-1:** (a) byte-identical `$krb5tgs$`/`$krb5asrep$` vs picky on GATE-0 fixtures;
  (b) live-fire DC01 = **6 TGS + 2 AS-REP**, hashglass modes 13100/19700/18200 (2026-09-20 baseline).
  **Rollback:** feature-flag off → picky roast path.

### K2 · AS/TGS/S4U/RBCD core — 3d

- **T2.1** `get_tgt`/`asktgt`/`get_tgt_by_hash`/`overpass_the_hash` full build+parse on kerbcore.
- **T2.2** `get_service_ticket` + AP-REQ (`build_ap_req_gss{,_aes256}`) via `build_ap_req_with_confounder`.
- **T2.3** S4U2Self + S4U2Proxy (`tgs.rs:932-1084`) + PA-FOR-USER checksum (`tgs.rs:993` →
  `KerberosKey::checksum`); `rbcd_impersonate{,_by_hash}`.
- **GATE-2:** RBCD end-to-end vs DC01 (set-password → add-spn → write-rbcd → enc-types →
  `rbcd --from-file` → AES256 service ticket), Rubeus/impacket parity as in 1.5.2 v5 receipt.
  **Rollback:** feature-flag off.

### K4 · unpac + crypto/codec sweep — 2d *(before forge — forge reuses these)*

- **T4.1** `unpac.rs:271-287` PAC_CREDENTIAL_INFO decrypt → `KerberosKey::decrypt`.
- **T4.2** `pac.rs:29 decrypt_ticket_pac` → kerbcore `EncTicketPart` (internal sig; verify no public leak per INV-1).
- **T4.3** Consolidate etype dispatch (`tgs.rs:74-98` manual branch) → `KerberosKey`; verify
  2025 `aes256-cts-hmac-sha384-192` via `rfc8009` (the etype seen in 2026-09-20 DCSync).
- **T4.4** Sweep remaining ~50 `picky_asn1_der` sites → `der`/`types`.
- **GATE-4:** `fuzz/fuzz_targets/pac_credential_info.rs` green (this is where the panic-abort
  crash lived — must be uncatchable-panic-free); unpac/U2U-NT live vs DC01.

### K3 · forge (golden/silver/diamond) — 2d — *most net-new code*

- **T3.1** Re-express `EncTicketPart` encode+encrypt on kerbcore `der`+`crypto`/`keys`
  (kerbcore ships NO forge). Keep `ms_pac_forge::ForgeIdentity`.
- **T3.2** `forge_golden_tgt`/`golden_ccache`, `forge_silver_tgt`/`silver_{ccache,service_ticket}`,
  `forge_diamond_tgt`.
- **GATE-3:** golden KDC-accepted (Domain+Enterprise+Schema Admins), silver forged w/ captured
  `$MACHINE.ACC`, diamond — vs DC01, per 1.5.2 top-10 receipt.

### P1 · PKINIT residual decision — 0.5d — *the honest boundary*

- **T P1.1** Lock **option (a):** keep `picky-asn1-x509` for `pkinit.rs` CMS/X.509 + `csr.rs`
  only. Move the PKINIT **AS-REQ** half (`pkinit.rs` KdcReq build/parse) to kerbcore `client`;
  leave AuthPack/CMS/DH + CSR on picky-asn1-x509.
- **T P1.2** Confirm `pkinit.rs`/`csr.rs` compile with ONLY picky-asn1-x509 (no picky-krb).
- **GATE-P1:** ESC1 → cert request → PKINIT → admin TGT ccache live vs DC01 (ADCS CA staged).
  **Note:** full picky kill = 1.6 **P-2** (hand-rolled `x509-min`/`ms-cms`, or vetted crate).

### K9 · retire picky-krb — 0.5d — *point of no return*

- **T9.1** Delete every `#[cfg(not(feature="kerbcore"))]` picky path; make kerbcore the only
  path; **remove the `kerbcore` feature gate** (it's just how the crate works now).
- **T9.2** Drop `picky-krb`, `picky-asn1`, `picky-asn1-der` from `crates/kerberos/Cargo.toml`.
  Confirm `Cargo.lock` no longer lists them (picky-asn1/-der may remain ONLY as
  picky-asn1-x509 transitive — verify that's the only source).
- **GATE-9:** INV-1 API diff empty; full ship-gate (§ship); no `picky_krb::` in tree.

### Parallel track X · live-fire fixes — 1.75d — *independent of K*

- **X-1** `run` accept `--dc` alias → seeds `--dns-server` (`cli/src/attacks/scan_anonymous.rs`
  or `run` clap struct); mirror the `--realm`↔`--domain` alias. **0.5d.** Gate: `run --dc <ip>`
  resolves lab SRV from Kali.
- **X-2** `scan` registry-ESC probe: make it reuse the same MS-RRP open path as `check wdigest`/
  `enum esc` (root-caused the 2026-09-20 skip↔found flip); add a StageChecklist reason line
  when skipped. **1d** (investigate first). Gate: 3 consecutive scans give identical ESC status.
- **X-3** `--version` fallback: registry build prints `1.5.3 (crates.io build)` not
  `(unknown, unknown)` (`build.rs`/vergen graceful default). **0.25d.**

### Parallel track C · CI (only when push authorized) 

- **C-1** push staged `.github/dependabot.yml` ignore rules; close the 10 blocked cargo PRs.
- **C-2** `@dependabot rebase` the 5 stale action PRs → green → merge safe ones (audit
  `upload-artifact 4→7`, `setup-python 5→7` against release/pages workflows first).
- **C-3** AFTER K9 + P-1: single coordinated PR — `picky-asn1-x509 0.14→0.15` (#12 re-eval) +
  RustCrypto 0.11 cohort (blocked until picky-asn1-x509 + adhammer-direct + kerbcore all align).

---

## Critical path & schedule

```
P0(0.5) → K1(2) → K2(3) → K4(2) → K3(2) → P1(0.5) → K9(0.5)  = 10.5d critical
X-1/X-2/X-3 (1.75d)  ── parallel, fold in anytime
C-track            ── gated on push authorization
```
**Core effort ≈ 10.5 engineering days** + 1.75d X (parallel) + ship 1.5d. Call it **~12d**.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| kerbcore forge gap (K-3) larger than 2d | med | high | K-3 is last on the K path; if it slips, ship K1-K4 behind feature, keep picky forge until 1.5.4 |
| DER re-encode not byte-identical (edge tags) | med | med | GATE-0 harness catches per-fixture before delete; INV-4 blocks removal |
| picky-asn1-x509 still pins old digest → RustCrypto 0.11 stays blocked | high | low | expected; C-3 is explicitly post-P2, not a 1.5.3 promise |
| public API leak (K4 EncTicketPart) | low | high | INV-1 grep gate; wrap in adhammer type if it leaks |
| 2025 AES-SHA2 etype mismatch | low | med | GATE-4 tests it directly against DC01 |

## Ship gate (1.5.3)

fmt clean · clippy `-D warnings` default **and** `--features rusthound-ce` · tests ≥466 +
byte-diff + X regressions · every K GATE green with a byte-diff receipt · live-fire DC01
(roast 6+2, dcsync krbtgt+Admin, golden/silver, ESC1→PKINIT, RBCD) redacted · INV-1 empty
API diff · MSRV 1.88 · no `[patch.crates-io]` · bottom-up `cargo publish --dry-run` ×12 first.

## Definition of done

`picky-krb`/`picky-asn1`/`picky-asn1-der` gone; `adhammer-kerberos` runs on `kerbcore` for
AS/TGS/roast/S4U/forge/unpac with an unchanged public API; panic-abort fuzz crash closed;
X-1/X-2/X-3 fixed; PKINIT/CSR isolated on picky-asn1-x509 (full retirement = 1.6 P-2);
dependabot resolvable. Nothing marked done in advance.
