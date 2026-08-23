# adhammer 1.4.3 — the "completion + defender polish" release

**Ship target:** 3-4 weeks after 1.4.2 pushes (early October 2026 if 1.4.2 pushes this week).
**Version:** `v1.4.3` (patch bump — additive features, no CLI breaks).
**Prep state:** 1.4.2 must be pushed to crates.io first (bumping the tainted 1.4.1 slot).

**Standing rule (2026-08-24, user directive):** NO AI features in adhammer. No LLM API integration, no MCP server surface, no external inference calls, no Anthropic/OpenAI/Ollama/etc. deps. Rule-based / deterministic / dependency-free only. This kills WS-21 (Diego's AI narrative) and WS-22 (MCP mode) permanently.

## Grand narrative

Three coherent chapters:

1. **Deliver on 1.4.2's Phase 3 promises** — live-validate DCShadow modern push, MSSQL query, cross-forest golden. Ship the deferred wire code (WS-4 Phase 2 concrete Kerberos crypto + WS-13 CLI + WS-14 cross-trust).
2. **Close the classic-CVE + forest-trust gap** — noPac, Zerologon exploit-with-restore, forest-trust chain end-to-end. HTB CAPE trust-attacks module coverage.
3. **Defender polish** — clock skew handling (skewrun), tombstone reanimation audit (ghosthound), baseline diff (diego). Real DFIR-adjacent wins from the top-10 Rust AD scan.

## Scope — must-ship for 1.4.3

### Tier 1 — Phase 3 completions from 1.4.2 (must, blocks the "1.4.2 was real" story)

| ID | What | Effort | Blocks |
|---|---|---|---|
| WS-1-P3 | MSSQL live query — MSSQL Express install on 2025server1 (Microsoft PS one-liner) + smoke tests (`SELECT @@VERSION` / `EXEC xp_cmdshell 'whoami'` / `EXECUTE AS sa`) + capture rendered output for release notes | S 1d | none |
| WS-2-P3 | DCShadow live push against 2022server — pick benign attr (`description` on `lowuser`), capture original via `ldapsearch`, `attack dcshadow --drsuapi --push --target lowuser --attr description --value 'proven by 1.4.3'`, verify via `Get-ADUser`, restore original | S-M 2d | none |
| WS-4-P2 | Concrete `AesCtsHmacSha1KrbSealer` in `adhammer/crates/kerberos/src/rpc_seal.rs` (RFC 4121 + MS-KILE §3.4.5.4.1 DCE-style WRAP) + `RpcTcp::bind_sealed_kerberos` / `call_sealed_kerberos` wire in dcerpc + live-test sealed RPC bind to DC01 samr | L 5-6d | dcerpc 0.3.0 unyanking / publish |
| WS-13-CLI | `attack dns` CLI subcommand on top of the 1.4.2 `dns_record` helper — `--action add-a / modify-a / tombstone / delete` + `--dry-run` gate. Uses SD-detection to locate zone container | M 2d | none |
| WS-14 | `--allow-cross-trust` flag on `attack constrained` — before S4U2Proxy, request cross-realm referral TGT via existing `asktgt` machinery, use that as input to S4U2Proxy against target service in trusted realm. Docstring calls out selective-auth / RESTRICTED_ONLY blockers | M 3-4d | WS-4-P2 preferred (uses sealed bind for the S4U2Proxy call) |
| WS-8-P2 | PFX export on `attack shadowcred` ADD — real PKCS#12 (self-signed cert + PBE-SHA1-3KEY key-bag + HMAC-SHA1 MAC + DER encoder). Consider `p12` crate vs hand-roll (~500 LOC) | M 3d | none |

### Tier 2 — classic-CVE completion (was 1.4.2's "completion release" content)

| ID | What | Effort | Blocks |
|---|---|---|---|
| WS-A1 | **noPac** (CVE-2021-42278 + 42287) — LDAPS object-create + `unicodePwd` chain: create machine account (MAQ > 0), clear its SPN, rename `sAMAccountName` → `DC01`, AS-REQ TGT for `DC01`, rename back, S4U2Self as `Administrator` → DCSync-capable service ticket | L 5d | unpatched ≤2019 DC for positive validation (WS-E) |
| WS-A2 | **Zerologon exploit-with-restore** (CVE-2020-1472) — extend `ms-nrpc` on crates.io with offensive `NetrServerPasswordSet2`; adhammer CLI adds destructive `--exploit` path already gated with `--confirm-brick-risk` + restore-from-cleartext path already shipped in 1.3.10. Now real DCSync-after-empty-password | M 4d | unpatched ≤2020 DC (WS-E) |
| WS-B | **Forest-trust attack chain** — extract inter-realm trust key from `trustedDomain.trustAuthIncoming/Outgoing` via DRSUAPI bulk pull (extend `ms-drsr`) → forge inter-realm TGT with the trust key (extend `ms-pac-forge`) → S4U2Self → S4U2Proxy as DA in the trusted forest | M-L 4-5d | WS-E lab (needs a second forest with a trust) |

### Tier 3 — defender polish (top-10 Rust tool absorbs)

| ID | Source | What | Effort |
|---|---|---|---|
| WS-15 | skewrun | **Clock-skew handling** — new `crates/ad-time/` module (or standalone `ad-time` crate for dual-use publish). Detect DC time via CLDAP (opnum 3 rootDSE `currentTime` attribute) + NTP + Kerberos ping. Silently offset AS-REQ/TGS-REQ timestamps in `build_as_req` and `build_tgs_req`. No libfaketime — we're the sender, adjust in-code. Optional `--time-offset <±secs>` for manual override. | S 1d |
| WS-16 | ghosthound | **Tombstone reanimation audit** — new `check tombstones` command. LDAP query with SHOW_DELETED control on `CN=Deleted Objects,<base>`. Rule: "Principal X holds Reanimate-Tombstones EACL on Deleted-Objects container → can restore deleted admin Y and inherit their groups". Extend BloodHound-CE export with `CanReanimate` edge. Extend our 41 checks to 42 with `TombstoneReanimationPath`. | M 2d |
| WS-19 | diego | **Baseline diff** — `scan --baseline <prior.json>` loads a prior scan, diffs findings by (`id`, `affected_object`), emits three tagged sets: `[NEW]` (present now, absent before), `[RESOLVED]` (absent now, present before), `[SEVERITY-CHANGED]` (present in both with different severity). Renders in all 4 report formats (JSON: `baseline_diff` object; MD: three sections; HTML: color-coded diff cards; TXT: three counts). | S 1d |
| WS-F-krb | IronEye + Diego | **`setup krb5` enhancements** — already shipped `setup krb5` in 1.4.2 (WS-12). Add: `--auto` mode that scans the network for DCs via SRV, tries each until one responds with a TGT test, writes krb5.conf for the winner. Add: append-mode (`--append`) that adds a realm to an existing krb5.conf instead of overwriting. | S 1d |

### Tier 4 — ship hygiene

| ID | What | Effort |
|---|---|---|
| DCERPC-CLEAN | Fix 17 pre-existing clippy warnings in dcerpc (deprecated drsuapi tests, 8-arg builder, hex casing, doc formatting, dead `deferred_len`). BLOCKS dcerpc 0.3.0 publish | S 1d |
| DCERPC-0.3 | Publish `dcerpc 0.3.0` to crates.io — sealed-bind primitives (WS-4 Phase 1) + WS-4 Phase 2 concrete crypto | S 4h |
| MS-BKRP | Wire the scaffolded `ms-bkrp` (BackupKey Remote Protocol, opnum 0 `BackuprKey`) → publish `ms-bkrp 0.1.0`. Foundation for 1.4.6 DPAPI backup key extraction | M 2d |
| MS-XCEP | Wire the scaffolded `ms-xcep` (bundles MS-WSTEP) → publish `ms-xcep 0.1.0`. Unblocks proper ADCS ESC8 Web Enrollment relay in 1.4.4+ | M 2-3d |
| ADHAMMER-PUBLISH | Publish `adhammer 1.4.3` + 11 workspace crates bottom-up. Tag `v1.4.3`, push main + tags. Un-yank any transitive breakages from 1.4.1 fallout | S 1d |

## Cut / DEFERRED to 1.4.4 (do not chase in 1.4.3)

- **WS-C** wire hardening probes (LDAP CBT + SMB3 encryption negotiate) — save for 1.4.4 with WS-17/18
- **WS-D** `krb-listen` — per dual-use rule, folds into adhammer CLI as `attack krb-listen`, not a new crate. Push to 1.4.4.
- **WS-E** legacy DC matrix (2016/2019/2022 spin-up alongside existing 2025+2022) — depends on VM setup capacity. Push to 1.4.4 if lab isn't ready in the WS-A1/A2 window.
- **WS-F SCCM + SCOM enum** — genuinely 2-3d of new LDAP walkers + possibly new `ms-sccm` sibling. Push to 1.4.4.
- **WS-G ADIDNS full write** — 1.4.3 ships WS-13-CLI which covers A records; extend to SRV/CNAME/MX/TXT in 1.4.4.
- **WS-17/18/20/23/24** — all diego/ntdsextract2/kerlab absorbs → 1.4.4/1.4.5 per per-slot memory table.
- **WS-21/22** — REJECTED permanently ("no AI" rule).

## Total estimated effort

- Tier 1 must-ship: **13-17 days** of focused work
- Tier 2 CVE completion: **13-14 days**
- Tier 3 polish: **5 days**
- Tier 4 hygiene: **5-7 days**
- **Total ≈ 36-43 days** (~7-8 weeks full-time)

That's TOO BIG for one 3-4 week ship. **Realistic 1.4.3 must-cut list:**

### 1.4.3 committed (fits ~3.5 weeks)

- Tier 1 all (Phase 3 completions non-negotiable — closes 1.4.2's promises)
- WS-16 (tombstone audit — real net-new blue-team surface)
- WS-19 (baseline diff — small, ships defender polish)
- WS-15 (clock skew — tiny but massive UX win)
- Tier 4 ship hygiene (mandatory for the release)

### 1.4.3 stretch (only if Tier 1 wraps early)

- WS-A1 noPac (highest CVE priority)
- WS-F-krb setup krb5 --auto (small)

### Pushed to 1.4.4

- WS-A2 Zerologon exploit-with-restore
- WS-B forest-trust chain
- WS-C wire-hardening probes
- WS-D krb-listen
- WS-E legacy DC matrix
- WS-F SCCM/SCOM
- WS-G ADIDNS full write
- WS-17/18/20/23/24 (defender absorbs)

## Ship sequence

**Week 1:** WS-15 clock skew (1d) → WS-19 baseline diff (1d) → WS-1-P3 MSSQL live (1d, needs MSSQL Express install on 2025server1) → WS-13-CLI attack dns (2d) → WS-16 tombstone audit start (2d — end of week)

**Week 2:** WS-16 finish → WS-8-P2 PFX export (3d) → WS-2-P3 DCShadow live push (2d)

**Week 3:** WS-4-P2 concrete AES-CTS-HMAC-SHA1-96 sealer + rpc bind wire (5-6d — timebox strictly). If it doesn't fit, DEFER TO 1.4.4 with clear "primitives-only" note.

**Week 4 (0.5-1 week):** DCERPC-CLEAN 17 warnings + MS-BKRP + MS-XCEP publishes + Tier 4 ship hygiene + release commit + `cargo publish` sequence + `git tag v1.4.3 && git push --tags`

## Live-validation matrix

Every non-Phase-3 landing gets `cargo test --workspace` + `--dry-run` verification on DC01. Every Phase 3 item gets the actual live wire test with output captured for the release notes.

Wire-test matrix expanded from 1.4.2's 5-test-per-DC to 8-test-per-DC:
- dcsync krbtgt (existing)
- coerce --pipe spoolss (existing)
- coerce --pipe totallybogus clap gate (existing)
- enum sessions env fallback (existing)
- dcsync --all --yes --limit 3 (existing)
- **NEW:** dcshadow --drsuapi --push --dry-run (WS-2-P3 gate)
- **NEW:** scan --baseline (WS-19)
- **NEW:** attack dns --dry-run (WS-13-CLI)

## Non-goals

- No AI features (rule, standing forever)
- No new sibling protocol crates beyond `ms-bkrp` + `ms-xcep` + optional `ad-time`
- No cloud (Entra ID / AD FS / Azure) — permanent scope exclusion
- No CLI breaking changes (patch bump discipline)
- No un-yank of adhammer 1.4.1 sub-crates (they stay yanked as intentional skip)

## Success signals

- All Tier 1 items live-validated on at least one DC
- Workspace clippy `-D warnings` clean at Rust stable
- CHANGELOG.md 1.4.3 section written from `git log 1.4.2..HEAD` (not from memory — see [[reference-changelog-writing-discipline]])
- 8/8 live wire tests green on DC01 + 2022server
- `dcerpc 0.3.0` published clean (17 clippy fixes land first)
- Follow-on 1.4.4 plan doc scaffolded before ship day

## Files to update on ship day

- `Cargo.toml` version 1.4.2 → 1.4.3
- `CHANGELOG.md` new `## [1.4.3]` section
- `README.md` "What's new" refresh
- `.agents/adhammer-1.4.3-plan.md` — this doc — mark items DONE / DEFERRED
- Plan doc for 1.4.4 scaffolded from what got pushed out of 1.4.3
- Memory HEAD entry updated
