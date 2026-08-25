# adhammer 1.4.4 — HARD PLAN ("finish the offensive backlog")

**Status:** scaffold (created 2026-08-25 on the 1.4.3 ship). Carries the Tier-1
Phase-3 work descoped from 1.4.3 plus 1.4.3's own "Deferred to 1.4.4" list.
**Version:** `v1.4.4` — **patch bump, additive only, ZERO CLI breaks.**
**Precondition:** 1.4.3 tagged + published; `dcerpc 0.2.7` live (DONE 2026-08-25).

Rules of engagement, publish rules, minimum-bump/SemVer, delegation — **unchanged
from `.agents/adhammer-1.4.3-plan.md` §1**. No AI, no competitor names, on-prem AD
only, dual-use gate for new sibling crates, `cargo fmt` first, clippy `-D` clean,
real `include_bytes!` fixtures, typed errors at lib boundaries, bottom-up publish
with `--dry-run`, no premature crates.io publish.

---

## 1. Carryover from the 1.4.3 descope — Tier-1 Phase-3 (MUST)

> These shipped-scoped-then-descoped items are the 1.4.4 core. 1.4.3 delivered the
> Tier-0 "prove it, cover it" thesis (WS-PROOF, WS-COVERAGE 41→58, WS-19); the
> Phase-3 completions below were cut to ship the evidence work.

**WS-4-P2 — concrete Kerberos sealed RPC bind ★ TOP PRIORITY**
- `AesCtsHmacSha1KrbSealer` (RFC 4121 + MS-KILE §3.4.5.4.1 DCE WRAP) + dcerpc
  `RpcTcp::bind_sealed_kerberos` / `call_sealed_kerberos` wire. Phase-1 primitives
  (`WrapToken` codec, `KrbSealer` trait, PDU framers) already live in **dcerpc 0.2.7**.
- The concrete sealer + new bind methods are **additive** → ship as **dcerpc 0.2.8**
  (patch line; `^0.2` consumers unaffected). This is the hardened-DC unlock (Server
  2025 rejects NTLM LDAPS).
- Files: `crates/kerberos/src/rpc_seal.rs` (new), `dcerpc/src/transport.rs` + `pdu.rs`.
- Acceptance: sealed RPC bind to DC01 `\PIPE\lsarpc` completes with no fault on a
  channel-binding-enforcing DC; WrapToken codec byte-fixture unit test.
- Effort: L (5–6d, strict timebox — do NOT half-ship).

**WS-1-P3 — MSSQL live query** — prove `attack mssql` (`SELECT @@VERSION`,
`xp_cmdshell`, `EXECUTE AS LOGIN`) against MSSQL Express on 2025server1. Effort: S.

**WS-2-P3 — DCShadow modern live push** — push one benign attribute via DRSUAPI
opnums 17+5 against 2022server, verify, restore byte-for-byte. `--dry-run` gate
first. Effort: S–M.

**WS-13-CLI — `attack dns`** — CLI over the 1.4.2 `dns_record` helper
(`--action add-a|modify-a|tombstone|delete` + `--dry-run`). Effort: M.

**WS-8-P2 — real PFX export on `attack shadowcred` ADD** — emit real PKCS#12
(self-signed cert + PBE-SHA1-3KEY + HMAC-SHA1 MAC + DER); prefer ≤500 LOC hand-roll
over the `p12` crate (dep-minimalism). Round-trip: export → PKINIT. Effort: M.

## 2. 1.4.3's "Deferred to 1.4.4" list (as written)

- **WS-20** severity × confidence dual-axis scoring on every Finding (diego, no-AI).
- **WS-17** NTDS timeline + tree (`dump ntds --timeline` / `--tree`, extend `ntds-parse`).
- **WS-18** `util klist2kirbi` (Windows klist → .kirbi).
- **WS-23** keytab + `KRB5CCNAME` cred-detection cascade in `resolve_secret`.
- **WS-A1** noPac (CVE-2021-42278+42287) — MAQ chain; needs WS-4-P2 + unpatched ≤2019 DC.
- **WS-T4b/T4c** ms-bkrp / ms-xcep wire + publish (stretch).

## 3. Deferred further (1.4.5+)

WS-A2 Zerologon exploit-with-restore · WS-B forest-trust chain · WS-C wire-hardening
probes · WS-D `krb-listen` (CLI module, dual-use rule) · WS-E legacy-DC matrix
(2016/2019) · WS-F SCCM/SCOM enum · WS-G ADIDNS full write · WS-24 passive LLMNR/NBT.

## 4. Dependency ordering

```
dcerpc 0.2.8 (WS-4-P2 sealer) ──► WS-14 cross-trust · WS-A1 noPac
(independent) WS-1-P3 · WS-2-P3 · WS-13-CLI · WS-8-P2 · WS-20 · WS-17 · WS-18 · WS-23
Publish gate: dcerpc 0.2.8 ─► adhammer 1.4.4
```

## 5. Definition of done (to tag v1.4.4)

- [ ] WS-4-P2 sealed bind live-validated on DC01 (the box that rejects NTLM LDAPS).
- [ ] Each Tier-1 item live-validated on ≥1 DC, output captured.
- [ ] fmt clean · clippy `-D` clean · `test --workspace` green · MSRV re-verified.
- [ ] CHANGELOG `## [1.4.4]` from `git log 1.4.3..HEAD`.
- [ ] dcerpc 0.2.8 published clean (bottom-up, `--dry-run`).
- [ ] No AI dep, no competitor name, no CLI break, no un-yank.
