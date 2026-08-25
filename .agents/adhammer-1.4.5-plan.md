# adhammer 1.4.5 — HARD PLAN ("finish the offensive story + start closing the parity gap")

**Status:** authoritative execution plan for the release after 1.4.4 (SHIPPED 2026-08-26).
**Version target:** `v1.4.5` — additive, ZERO CLI breaks (patch line, per project convention).
**Thesis:** 1.4.4 finished the *reporting* story (in-report graph + coverage matrix + evidence).
1.4.5 finishes the *offensive* story that 1.4.2/1.4.3 kept deferring, and takes the first concrete
bites out of the "Rust isn't a full impacket/C# ecosystem yet" gap — the honest weak point.

---

## 0. Preconditions (all true before 1.4.5 work starts)

1. 1.4.4 is live on crates.io + tag `v1.4.4` (DONE 2026-08-26, live-validated 2025 DC).
2. Disk ≥ 25 GB free (cold workspace build ≈ 2.5 GB; dry-runs + toolchains need slack).
3. Every touched repo committed & clean at session start.
4. Lab up: testlab.local — 2019 / 2022 / 2025 DCs (all reachable on 636 as of 2026-08-26).
   Creds live in `Desktop\CYBERSEC.md`, never in this file or any committed doc.

---

## 1. RULES OF ENGAGEMENT (non-negotiable — violating any = stop)

- **NO AI features, ever.** No LLM/API/MCP/ML dep. English narrative stays rule-based/deterministic.
- **No competitor names** in shipped code/docs/README/Cargo descriptions. Allowed only in
  `docs/BENCHMARKS.md`, `bench/*`, and genuine interop labels (e.g. "MIT ccache").
- **On-prem AD only.** Entra/hybrid/AD FS/Azure/PRT are permanent scope exclusions.
- **Real proof, never our word.** Every new attack/enum ships with a **live-DC capture** in
  `docs/VALIDATION.md` before it's called done. No blind wire code — if it can't be validated on
  a lab DC this cycle, it does NOT ship (defer, don't half-ship).
- **Dual-use gate for new sibling crates.** Extract a standalone crate only if the primitive has
  genuine defensive/DFIR reuse. Attacker-only compositions stay inside the adhammer CLI.
- **Minimum-bump / SemVer honesty** on every crate (workspace + siblings) — verify the real
  pub-API delta before bumping; additive ⇒ stay on the line.
- **Engineering gate every session:** `cargo fmt --all` FIRST → `clippy --workspace --all-targets
  -D warnings` clean → `cargo test --workspace` green → live-validate → commit. Wire parsers get a
  fuzz target + clean run before publish. Bounded-alloc preflight on every wire-derived length.
- **Publish is irreversible + the user's explicit call.** Bottom-up, `--dry-run` first, tag after.
  Never `git add -A`; `git -c commit.gpgsign=false`; never `Co-Authored-By: Claude`.

---

## 2. Workstreams

> Each WS: **Goal · Files · Effort (S ≤1d / M 2–3d / L 4–6d) · Depends · Acceptance · Verify · Rollback.**

### Tier 1 — finish the deferred offensive Phase-3 (MUST — closes the "1.4.2 was real" story)

**WS-4-P2 — concrete Kerberos sealed RPC bind ★ TOP PRIORITY (the multi-day one)**
- Goal: `AesCtsHmacSha1KrbSealer` (RFC 4121 + MS-KILE §3.4.5.4.1 DCE-style WRAP) +
  `RpcTcp::bind_sealed_kerberos` / `call_sealed_kerberos`. Phase-1 primitives (WrapToken codec,
  `KrbSealer` trait, PDU framers) already shipped in dcerpc 0.2.7 — this is the concrete crypto.
- Files: `crates/kerberos/src/rpc_seal.rs` (new), `dcerpc/src/transport.rs` + `pdu.rs` (bind path).
- Effort: **L** — timebox strictly to one focused pass. If it slips, ship **primitives-only** and
  defer concrete to 1.4.6; do NOT half-ship a broken sealer.
- Depends: dcerpc **0.2.8** (additive; the sealer is what justifies the bump).
- Acceptance: sealed RPC bind to the 2025 DC `\PIPE\lsarpc` completes with no fault on a
  channel-binding-enforcing DC; round-trips one opnum.
- Verify: live on 2025 DC (the box that rejects unsigned binds); real byte-fixture unit test for
  the WrapToken codec; fuzz the token parser.
- Rollback: feature-gate the sealer; NTLM/SMB seal paths untouched.

**WS-1-P3 — MSSQL live query (cheap win, do first)**
- Goal: prove `attack mssql` end-to-end against a real MSSQL Express (exercises `ms-tds`).
- Files: none new; capture output for `docs/VALIDATION.md`.
- Effort: **S** · Depends: MSSQL Express on a lab member/DC (PS one-liner install).
- Acceptance: `SELECT @@VERSION`, `EXEC xp_cmdshell 'whoami'`, `EXECUTE AS LOGIN` return real rows.
- Verify: live capture; `cargo test -p ms-tds` green. Rollback: n/a (read-only proof).

**WS-2-P3 — DCShadow modern live push (cheap win)**
- Goal: push one benign attribute via DRSUAPI opnums 17+5 against 2022, verify, restore.
- Files: existing dcshadow path; no new code expected.
- Effort: **S–M** · Depends: 2022 DC, DA creds.
- Acceptance: set `description` on a lab user → confirm via `Get-ADUser` → restore byte-for-byte.
- Verify: `--dry-run` gate first; capture before/after. Rollback: script the original capture BEFORE the push.

**WS-8-P2 — real PFX export on `attack shadowcred` ADD**
- Goal: emit real PKCS#12 (self-signed cert + PBE-SHA1-3KEY key bag + HMAC-SHA1 MAC + DER).
- Files: small `pfx` module in `crates/kerberos/`; hand-roll ≤ ~500 LOC (dep-minimalism + dual-use).
- Effort: **M** · Depends: none.
- Acceptance: exported `.pfx` imports into the Windows cert store AND is accepted by our own PKINIT.
- Verify: round-trip (export → PKINIT auth) live; byte-fixture unit test. Rollback: keep raw-key output behind a flag.

### Tier 2 — start closing the impacket/C# parity gap (the honest weak point)

> Pick the highest-leverage missing primitives. Each is a **standalone dual-use crate** (defenders
> and DFIR use DCOM/SCM too) then an adhammer CLI verb over it. Do NOT boil the ocean — 1.4.5 lands
> **one** of these fully, scaffolds the next. Priority order below.

**WS-P1 — `ms-scmr` full + `attack exec --method smb` (psexec-style)** ★ best first parity win
- Goal: MS-SCMR over the existing sealed SMB pipe — `OpenSCManagerW` → `CreateServiceW` (binary
  path or `%COMSPEC% /c` output-to-share) → `StartServiceW` → `DeleteService` cleanup. Remote code
  execution as SYSTEM, the single most-requested missing verb vs the Python/C# toolkits.
- Files: `ms-scmr` sibling crate (extend the 115-LOC scaffold to full opnums 12/15/2/16/13),
  `cli/src/attacks/exec.rs` (new, `--method smb`). Output capture via a temp share read-back.
- Effort: **L** · Depends: **WS-4-P2 preferred** (sealed bind for hardened DCs); ms-scmr bump → own publish.
- Acceptance: `whoami` returns `nt authority\system` from a low-priv-but-local-admin context on the
  lab member; service artifact is created AND deleted (no residue). Clean, clear failure on access-denied.
- Verify: live on 2022 member; unit test the CreateServiceW NDR framing against a byte fixture.
- Rollback: attacker-only → stays in the CLI, not a public attack crate; feature-gate the exec verb.

**WS-P2 — `ms-dcom` + `ms-wmi` scaffold → `attack exec --method wmi` (dcomexec/wmiexec-style)**
- Goal: the biggest structural gap — a native DCOM activation (`IRemoteSCMActivator`,
  `IWbemLevel1Login` → `IWbemServices::ExecMethod` `Win32_Process.Create`) so RCE works from Linux
  with no Windows COM runtime. 1.4.5 lands the **DCOM base + OXID resolver + one WMI method**; full
  IWbem surface is 1.4.6.
- Files: `ms-dcom` (new sibling — DUAL-USE: admin/DFIR tools want DCOM too), `ms-wmi` (new sibling).
- Effort: **L** (scaffold only this cycle) · Depends: dcerpc auth binds, WS-4-P2 for sealed activation.
- Acceptance: OXID resolution + `Win32_Process.Create('cmd /c ...')` returns a PID on the lab member.
- Verify: live; NDR fixtures for the activation blobs. Rollback: new crates, no impact if unshipped.

**WS-P3 — `ccache-io` (MIT ccache + `.kirbi` read/write) ★ interop, low effort/high value**
- Goal: import/export Kerberos tickets to/from the standard MIT `krb5cc` and Windows `.kirbi`
  formats, so tickets forged/roasted by adhammer interoperate with the rest of a toolkit (and vice
  versa). Closes the "adhammer is an island" complaint without any new attack surface.
- Files: `ccache-io` (new sibling — DUAL-USE: DFIR/admin ticket inspection), wired into
  `crates/kerberos` (write on forge, read on `--ticket <file>`).
- Effort: **M** · Depends: none. Pure format codec — fully offline-testable.
- Acceptance: a golden ticket adhammer forges exports to `krb5cc`, is accepted by a standard client;
  a `.kirbi` from an external tool imports and PtT works. Rollback: additive; no behavior change absent the flags.

### Tier 3 — coverage + polish (soft targets, only if Tier 1 wraps early)

- **WS-COVERAGE 58 → 70** — the SYSVOL/live-probe classes that need the collector, not LDAP reads:
  GPP `cpassword` sweep surfaced as findings, print-spooler / WebClient (WebDAV) exposure,
  LDAP-signing / channel-binding posture as passive findings, AdminSDHolder ACL drift. Each
  evidence-backed; surfaced in the coverage matrix. Effort: **M**.
- **WS-16 — tombstone-reanimation audit** (`check tombstones`, LDAP `SHOW_DELETED`) + `CanReanimate`
  BH-CE edge. Effort: **M**.
- **WS-19b — baseline diff in the interactive/guided flow** (currently `scan --baseline` only). Effort: **S**.

---

## 3. Dependency ordering (respect the DAG)

```
dcerpc 0.2.8 (WS-4-P2 sealer) ──┬─► WS-P1 (ms-scmr exec, hardened DCs need sealed bind)
                                └─► WS-P2 (ms-dcom sealed activation)
ms-scmr ext ─► attack exec --method smb
ms-dcom + ms-wmi ─► attack exec --method wmi
(independent, offline) WS-1-P3 MSSQL · WS-2-P3 DCShadow · WS-8-P2 PFX · WS-P3 ccache-io · Tier-3
Publish gate: dcerpc 0.2.8 ─► (adhammer consumes) ; ms-scmr/ms-dcom/ms-wmi/ccache-io ─► adhammer
```

---

## 4. Committed vs stretch vs deferred

**1.4.5 COMMITTED (fits ~3.5 weeks):** Tier-1 all (WS-4-P2 timeboxed, WS-1-P3, WS-2-P3, WS-8-P2)
· **one** Tier-2 parity win fully (recommend **WS-P3 ccache-io** [cheap, offline] + **WS-P1 ms-scmr**
[highest-leverage]) · dcerpc 0.2.8 publish · adhammer 1.4.5 publish + tag.

**Stretch (only if Tier-1 wraps early):** WS-P2 DCOM/WMI scaffold · WS-COVERAGE 58→70 · WS-16.

**Deferred → 1.4.6:** full IWbem WMI surface · MS-FSRVP (VSS coerce) · MS-WKST/MS-SRVS session+share
enum · `execute-assembly`/BOF Windows in-memory story · legacy-DC matrix (2016).

**Permanently rejected:** any AI narrative / MCP mode ("no AI" rule).

---

## 5. Ship sequence (week-by-week)

- **Week 1:** WS-1-P3 MSSQL (1d) → WS-2-P3 DCShadow (2d) → WS-P3 ccache-io (2–3d, offline-testable).
- **Week 2:** WS-8-P2 PFX (3d) → start WS-P1 ms-scmr.
- **Week 3:** WS-4-P2 sealed bind (**make-or-break**, strict timebox; primitives-only fallback) →
  finish WS-P1 exec over the sealed bind.
- **Week 4 (0.5–1):** dcerpc 0.2.8 publish → ms-scmr publish → release commit → `--dry-run` chain →
  adhammer 1.4.5 publish bottom-up + tags → `docs/VALIDATION.md` refreshed with every live capture.

---

## 6. Definition of done (all must hold to tag v1.4.5)

- [ ] Every Tier-1 + shipped Tier-2 item **live-validated on ≥1 DC/member, capture in `docs/VALIDATION.md`**.
- [ ] `cargo fmt --all --check` clean; `clippy --workspace --all-targets -D warnings` clean.
- [ ] `cargo test --workspace` green (≥194 + new WS tests); every new wire test uses a real fixture.
- [ ] New wire parsers fuzzed (clean run) before their crate publishes.
- [ ] MSRV re-verified for any crate touched; `rust-version` accurate.
- [ ] `CHANGELOG.md ## [1.4.5]` written from `git log v1.4.4..HEAD` (not memory).
- [ ] dcerpc 0.2.8 + any new sibling crates published bottom-up with dry-runs; adhammer 1.4.5 + tag.
- [ ] No AI dep, no competitor name, no CLI break, no un-yank of 1.4.0/1.4.1 sub-crates.

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| WS-4-P2 crypto slips the timebox | Med | High (blocks WS-P1/P2 on hardened DCs) | strict Week-3 box; ship primitives-only, defer concrete to 1.4.6 |
| DCOM (WS-P2) is a rabbit hole | High | Med | scaffold-only this cycle (OXID + one method); do NOT attempt full IWbem |
| exec/psexec residue on a lab DC | Low | Med | mandatory DeleteService cleanup + verify no artifact; member host, not a DC |
| Session-limit kills a long agent run | Med | Med | commit/push before big runs; "commit partial + note next" escape hatch |
| Publishing untested wire code | Low | High | hard rule — no ship without a live capture; defer over half-ship |
