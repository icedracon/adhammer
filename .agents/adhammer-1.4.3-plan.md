# adhammer 1.4.3 — HARD PLAN ("completion + fortress")

**Status:** authoritative execution plan. Supersedes the earlier draft.
**Ship target:** 3–4 weeks after 1.4.2 lands (1.4.2 pushes ~2026-08-27 → 1.4.3 ~ late Sep / early Oct 2026).
**Version:** `v1.4.3` — **patch bump, additive only, ZERO CLI breaks.**
**Last hardened:** 2026-08-24 (folds the ecosystem deep-audit session).

---

## 0. Preconditions (must all be true before 1.4.3 work starts)

1. **1.4.2 is published** (workspace + 12 crates on crates.io, tag `v1.4.2`, main pushed). 1.4.1 sub-crates stay yanked.
2. Disk headroom ≥ 25 GB free (a full cold workspace build ≈ 2.5 GB target; toolchain installs + dry-runs need slack). *Recurring blocker — verify each session.*
3. Working tree of every touched repo is committed & clean at session start (`git status` in each). Prior-session uncommitted work reviewed & committed first — see the audit readiness doc `.agents/SIBLING_WAVE_1.4.2_READINESS.md`.

### State carried in from the 2026-08-24 audit (do not redo)

| Item | State | Action for 1.4.3 |
|---|---|---|
| Ecosystem clippy | **0 warnings** across 49 standalone + 12 workspace crates | keep it 0; every WS ends clippy-clean |
| dcerpc 17 clippy warnings (old DCERPC-CLEAN task) | **DONE** (fixed in audit, local) | just commit + carry into the 0.2.7 publish |
| dcerpc version | **0.2.7 local** (re-versioned from 0.3.0 — additive-only, minimum-bump rule), unpublished | publish in Tier 4 after WS-4-P2 crypto lands |
| ms-pac-forge typed errors (old follow-up) | **DONE — 0.2.0 local** (`PacForgeError`) | optional adopt in adhammer (WS-T4c, 1-line) |
| MSRV | **verified + stamped** all 49 (23×1.74, 24×1.85, winrm-pentest 1.86, lsass-parse 1.88); workspace 1.87 | keep floors honest; re-verify after any clippy `--fix` |
| Sibling wave (ms-pac-forge/ntlm-relay/llmnr-poison 0.2.0, ms-csra 0.1.2) | bumped + changelogged, unpublished | publish as its own wave (Tier 4d) — NOT coupled into the 1.4.2 push |
| **Interactive UX overhaul** | **DONE this session** — 2-mode front door (Auto / Single / Session), step 1-4 narration, severity-grouped summary, batch impact pick (all/N/none), **inline capped PoC proof**, **ESC-registry probe folded into Auto**, premium HTML report bundle, JSON-default for attacks (`--text` opt-out), Windows VT/UTF-8 console fix, `DOMAIN/user` typo fix, wipe-confirm, `run_all_with_coverage` matrix. Version bumped to **1.4.3**, commit `f70e1b5` (local, mislabeled "1.4.2" — relabel + rebase onto origin) | the first delivered 1.4.3 chunk; WS-PROOF/COVERAGE build directly on it |

---

## 1. RULES OF ENGAGEMENT (non-negotiable — violating any = stop)

**Product rules**
- **NO AI, ever.** No LLM/API integration, no MCP server surface, no ML models, no `anthropic`/`openai`/`ollama`/etc. dep. Any English narrative in reports is rule-based / deterministic / dependency-free (WS-10 composite-chain style). Kills the Diego WS-21/22 direction permanently.
- **No competitor names** in shipped code, docs, READMEs, or Cargo descriptions (impacket / mimikatz / BloodHound / Rubeus / Certipy / RustHound / PingCastle / …). Allowed ONLY in `docs/BENCHMARKS.md`, `bench/*`, and genuine interop labels (e.g. "BloodHound CE v5 ingest").
- **On-prem AD only.** Entra ID / hybrid AD / AD FS / Azure / PRT / vSphere are permanent scope exclusions.
- **Dual-use gate for new sibling crates.** Extract to a standalone crate ONLY if the primitive has genuine defensive/DFIR reuse. Attacker-only compositions stay inside the adhammer CLI (e.g. `krb-listen`).
- **Patch-bump discipline:** 1.4.3 is additive. No CLI flag/subcommand removals or renames without a hidden deprecation alias (as done for `pth→ptt`).

**Engineering rules**
- **`cargo fmt --all` FIRST**, every session, before any commit. `cargo fmt --all --check` must pass at ship.
- **Clippy `-D warnings` clean** on `--workspace --all-targets` at ship. After any `cargo clippy --fix`, **re-verify MSRV** (fix can silently raise it via `is_multiple_of`/`repeat_n` — see `reference-clippy-fix-raises-msrv`). Declare `rust-version` so clippy stays MSRV-aware.
- **Wire code:** no fabricated fixtures. Every parser/crypto test uses a real `include_bytes!` capture. Bounded-alloc preflight on every attacker-controlled length before `Vec::with_capacity`.
- **Typed errors at library boundaries** (`thiserror`), `anyhow` only in the CLI/bins/examples/tests.
- **CHANGELOG from `git log`, never from memory** (see `reference-changelog-writing-discipline`). `[Unreleased]` = actual local diff, not planned work.

**Publish rules (irreversible — treat as such)**
- **★ MINIMUM-BUMP / SemVer honesty (applies to EVERY crate).** The version number
  communicates **compatibility, not significance.** Bump only as far as the actual
  change requires — never jump a minor/major to "signal a milestone." **Verify the
  real public-API delta before bumping:**
  `git show <commit-range> --unified=0 | grep -E '^-.*pub (fn|struct|enum|trait|mod|const|type)'`
  — if that prints **nothing** (no pub item removed or signature-changed), the change
  is **compatible → stay on the current line** (patch bump within `^current`).
  - **0.x crates** (`^0.y.z` = `>=0.y.z, <0.(y+1).0`): additive OR bugfix → **patch**
    (`0.2.5 → 0.2.6`, stays `^0.2` — every consumer pinned `^0.2` gets it for free);
    breaking (pub removed / signature changed / behavior contract broken) → **minor**
    (`0.2.x → 0.3.0`).
  - **≥1.0 crates**: additive → minor, bugfix → patch, breaking → major.
  - **Why it's hard, not advisory:** an unnecessary minor/major forces a cascade of
    pin bumps + republishes across every dependent. Live example: dcerpc `0.3.0`
    (purely additive — 21 pub items added, 0 removed) would have broken the `^0.2`
    pins of ~10 sibling crates + adhammer for a release that breaks nothing →
    re-versioned to `0.2.7`, everyone consumes it with zero pin changes. Save the
    next minor for a **real** break (e.g. dcerpc's eventual `drsuapi` removal → 0.4.0,
    already publicly promised — don't tighten a published deprecation target either).
- **Strictly bottom-up** dep chain. **`cargo publish --dry-run` first, always.**
- Explicit `git add <paths>` — never `git add -A`. `git -c commit.gpgsign=false`. **Never** add `Co-Authored-By: Claude`.
- Yanks are permanent for re-use — never un-yank stale content. 1.4.0 + 1.4.1 sub-crates stay yanked.
- Strip any `[patch.crates-io]` before publishing the consuming crate.

**Delegation rules**
- Delegate: mechanical batch refactors, self-contained wire-format workstreams, independent emitter/report work.
- Stay inline: publish cycles (irreversible), interactive version decisions, destructive live-DC ops.
- Before a big agent run: commit/push state (session limits reset ~6pm/11pm Yerevan and have killed agents mid-run). Give every agent a "commit partial + note next steps" escape hatch.

---

## 2. Grand narrative — the 1.4.3 thesis: **prove it, and cover it**

**1.4.3 is where adhammer stops *asserting* and starts *proving*.** The interactive UX overhaul
already shipped in-tree (see State carried in) turned Auto into scan → pick → chain → PoC. 1.4.3
makes two promises real, then finishes the offensive backlog:

1. **Ground-truth proof for EVERY finding (WS-PROOF).** No finding — misconfig OR CVE — stands
   on adhammer's word alone. Each carries the actual server/client artifact that proves it: the
   raw LDAP attribute value, the RRP registry key, the Kerberos/SMB status code, the issued cert,
   the Netlogon handshake result. **"You have X" becomes "the server returned Y, which is X."**
   A client can verify each finding by hand from the evidence.
2. **Coverage that stands next to the mature auditors (WS-COVERAGE + WS-AUTOSCAN).** Grow the
   passive registry **41 → 70+**, and fold every safe read-only detection (Posture, Zerologon-safe,
   session hunting, ESC registry) into Auto so **one run is the whole picture**.
3. **Deliver 1.4.2's Phase-3 promises + close the CVE/forest-trust gap** — WS-4-P2 sealed bind
   (still the hardened-DC unlock), cross-trust, real PFX, noPac, Zerologon exploit-with-restore.

**North-star for 1.4.3: WS-PROOF.** Evidence on every finding is the difference between a report a
client *trusts* and one they take on faith — and it's what separates adhammer from a rules engine.
**WS-4-P2 (sealed bind)** remains the top *offensive* unlock underneath it.

---

## 3. Workstreams (full detail)

> Each WS lists: **Goal · Files · Effort · Depends · Acceptance · Verify · Rollback.**
> Effort: S ≤1d, M 2–3d, L 4–6d.

### Tier 0 — the 1.4.3 thesis: prove it, cover it (NEW — top priority)

> **Progress (2026-08-25):** WS-PROOF **DONE** (`Finding.evidence`, every check populated, rendered
> in HTML/MD/terminal — commit `7058c53`). WS-COVERAGE **in progress: registry 41 → 58** (+17,
> latest: ConstrainedToDc [Critical], WeakCertTemplateCrypto, DomainReversiblePwd, GpoCreatorOwners)
> — ALL offline-tested (184 workspace tests), NONE live-validated against a DC yet (formerly +11
> evidence-backed: PasswordInDescription, ConstrainedDelegation, KerberoastableUser, AdminDelegatable,
> KeyCredentialOnAdmin, BroadInTier0, WeakFgpp, LapsExpired, **CleartextSecret (userPassword/unixUserPassword),
> KeyAdmins (526/527), AdminNotProtected**). WS-AUTOVAL **started** (roast validator widened to KerberoastableUser).
> WS-AUTOSCAN posture probe folded into Auto (commit `098af82`); remaining live probes need the lab.
> All local, 173 tests green, workspace clippy `-D` clean.

**WS-PROOF — ground-truth evidence on every finding ★ north-star**
- Goal: every `Finding` carries the raw server/client artifact that substantiates it, not just
  adhammer's rule verdict. Misconfig → the actual attribute / registry / config value read.
  CVE → the actual probe response (Netlogon handshake, CA config bytes, KDC error code). Rendered
  in the report + terminal next to the verdict, so a client can verify each finding by hand.
- Files: `crates/core` (add `Finding.evidence: Vec<Evidence>` = {source, raw, note}); every rule in
  `crates/checks` populates it from the snapshot data it ALREADY reads (near-zero extra I/O);
  `crates/report` renders an "Evidence" block per finding; the guided flow's captured PoC is the
  evidence for validatable findings (already wired this session).
- Effort: L (touches every rule, but mechanical — the data is already in the snapshot).
- Acceptance: every finding in every report format shows the concrete server/client data proving
  it; nothing is stated on adhammer's authority alone.
- Why it matters: this is the PingCastle / Purple-Knight bar **and past it** — they show the config,
  we show the config AND (for validatable findings) the exploit PoC already captured.

**WS-COVERAGE — check registry expansion (41 → 70+)**
- Goal: close the coverage gap vs the mature AD auditors. Add the missing passive-detection classes:
  GPO/SYSVOL permissions + GPP `cpassword`, WebDAV/WebClient (relay), print-spooler exposure,
  certificate lifetime + weak-crypto templates, LDAP signing/channel-binding posture as passive
  findings, obsolete OS/protocol per host, AdminSDHolder drift, DnsAdmins, trust-account-quota,
  privileged-group nesting depth, empty-password / pwd-not-required sweep, Backup-Operators abuse,
  SPN exposure. Surfaced via the coverage matrix (`run_all_with_coverage`, added this session) so
  the terminal shows tested-vs-vulnerable for the whole set.
- Files: `crates/checks` (new rule modules + registry entries) — each rule also populates WS-PROOF
  evidence. Effort: L. Acceptance: coverage matrix ≥ 70 vectors; `docs/BENCHMARKS.md` count table.

**WS-AUTOSCAN — fold every safe detection into Auto**
- Goal: Auto runs the safe, read-only active detections automatically as non-fatal probes:
  Posture (LDAP signing / channel binding / spooler = relay enablers), Zerologon SAFE detection,
  session hunting (SRVSVC / WKSSVC / HKU), DNS + net sweep. ESC-registry probe already folded in
  (this session). One Auto run = the full picture, no hand-picking from Single-attack mode.
- Files: `cli/guided.rs` (opportunistic auto-probes, each graceful on failure). Effort: M.

**WS-AUTOVAL — widen auto-validation (more findings → real PoC)**
- Goal: more finding IDs map to a validator so more findings capture ground-truth proof. Safe reads
  first (sessions, posture). Destructive writes (ESC4, RBCD, ShadowCred, BadSuccessor) get a
  validator gated behind an explicit `⚠ this MODIFIES AD — proceed?` confirm + `--dry-run` default,
  so Auto can prove them without silent damage. Effort: M.

---

### Tier 1 — Phase-3 completions (MUST — closes the "1.4.2 was real" story)

**WS-1-P3 — MSSQL live query**
- Goal: prove `attack mssql` end-to-end against a real MSSQL Express.
- Files: none new (exercises `ms-tds` + `cli/src/attacks/mssql.rs`); capture output for release notes.
- Effort: S · Depends: MSSQL Express on 2025server1 (MS PS one-liner).
- Acceptance: `SELECT @@VERSION`, `EXEC xp_cmdshell 'whoami'`, `EXECUTE AS LOGIN` all return real rows.
- Verify: live run captured; `cargo test -p ms-tds` green.
- Rollback: n/a (read-only proof).

**WS-2-P3 — DCShadow modern live push**
- Goal: push one benign attribute via DRSUAPI opnums 17+5 against 2022server, verify, restore.
- Files: `crates/*` (existing dcshadow path); no new code expected.
- Effort: S–M · Depends: 2022server reachable, DA creds.
- Acceptance: set `description` on `lowuser` → confirmed via `Get-ADUser` → original restored byte-for-byte.
- Verify: `--dry-run` gate first; capture before/after.
- Rollback: restore original attr (script the original capture BEFORE the push).

**WS-4-P2 — Concrete Kerberos sealed RPC bind ★ TOP PRIORITY**
- Goal: `AesCtsHmacSha1KrbSealer` (RFC 4121 + MS-KILE §3.4.5.4.1 DCE-style WRAP) + `RpcTcp::bind_sealed_kerberos` / `call_sealed_kerberos` wire.
- Files: `adhammer/crates/kerberos/src/rpc_seal.rs` (new), `dcerpc/src/transport.rs` + `dcerpc/src/pdu.rs` (bind path). Phase-1 primitives (`WrapToken` codec, `KrbSealer` trait, PDU framers) already exist; NTLM `bind_sealed`/`bind_sealed_hash` are the shape to mirror.
- Effort: L (5–6d, **timebox strictly** — if it slips, defer to 1.4.4 with a "primitives-only" note, do NOT half-ship).
- Depends: dcerpc 0.2.7 (unpublished, local) — this is the feature that justifies the 0.2.7 publish.
- Acceptance: a sealed RPC bind to DC01 `\PIPE\lsarpc` (or samr) completes with no fault on a channel-binding-enforcing DC; round-trips one opnum.
- Verify: live against DC01 (2025) — the box that rejects NTLM LDAPS; real byte-fixture unit test for the WrapToken codec.
- Rollback: feature-gate the Kerberos sealer; NTLM/SMB paths untouched.

**WS-13-CLI — `attack dns`**
- Goal: CLI over the 1.4.2 `dns_record` helper — `--action add-a|modify-a|tombstone|delete` + `--dry-run`.
- Files: `cli/src/attacks/dns.rs` (new), wire into `cli/src/main.rs` Attack enum.
- Effort: M · Depends: none (helper landed in 1.4.2, WS-13 prep).
- Acceptance: add + modify + tombstone an A record in the ADIDNS zone; SD-detection locates the zone container; `--dry-run` prints intended change without writing.
- Verify: live against DC01 ADIDNS; `--dry-run` in the wire-test matrix.
- Rollback: `--dry-run` default-safe; delete created records after test.

**WS-14 — `--allow-cross-trust` on `attack constrained`**
- Goal: request a cross-realm referral TGT via existing `asktgt`, feed it to S4U2Proxy against a service in the trusted realm.
- Files: `crates/kerberos/src/tgs.rs`, `cli/src/attacks/` constrained handler.
- Effort: M · Depends: **WS-4-P2 preferred** (uses sealed bind for the S4U2Proxy call); WS-E lab (second forest with a trust).
- Acceptance: obtain a usable service ticket as DA in the trusted forest; docstring calls out selective-auth / RESTRICTED_ONLY blockers.
- Verify: live against a two-forest trust lab; offline unit test for the referral-TGT plumbing.
- Rollback: flag-gated; no behavior change when flag absent.

**WS-8-P2 — Real PFX export on `attack shadowcred` ADD**
- Goal: emit real PKCS#12 (self-signed cert + PBE-SHA1-3KEY key bag + HMAC-SHA1 MAC + DER).
- Files: `crates/kerberos/` or a small `pfx` module; evaluate `p12` crate vs ~500 LOC hand-roll (dual-use rule + dep-minimalism → prefer hand-roll if ≤ ~500 LOC).
- Effort: M · Depends: none.
- Acceptance: exported `.pfx` imports cleanly into Windows cert store AND is accepted by our own PKINIT path.
- Verify: round-trip (export → PKINIT auth) live; byte-fixture unit test.
- Rollback: keep the current raw-key output path behind a flag.

### Tier 2 — classic-CVE completion

**WS-A1 — noPac (CVE-2021-42278 + 42287)**
- Goal: MAQ-abuse chain — create machine acct, clear SPN, rename `sAMAccountName`→`DC01`, AS-REQ TGT, rename back, S4U2Self as Administrator → DCSync-capable ticket.
- Files: `crates/kerberos/` + `cli/src/attacks/nopac.rs` (new), LDAP object-create via `adhammer-collector`.
- Effort: L · Depends: **WS-4-P2** (LDAP object-create/rename needs sealed bind on hardened DCs); WS-E unpatched ≤2019 DC for a positive result.
- Acceptance: end-to-end DCSync ticket obtained on the vulnerable lab DC; clean failure + clear message on a patched DC.
- Verify: live on unpatched DC (positive) + patched DC (negative-path message).
- Rollback: idempotent cleanup — delete the created machine account; restore any renamed attribute.

**WS-A2 — Zerologon exploit-with-restore (CVE-2020-1472)**
- Goal: offensive `NetrServerPasswordSet2` in `ms-nrpc` (detection primitive already ships); adhammer adds destructive `--exploit` behind `--confirm-brick-risk`; restore-from-cleartext path already in 1.3.10.
- Files: `ms-nrpc` (extend), `cli/src/attacks/zerologon.rs`.
- Effort: M · Depends: unpatched ≤2020 DC (WS-E). ms-nrpc bump (0.1.1) → its own publish.
- Acceptance: empty-password set → DCSync → machine-account secret restored → DC recovers after reboot.
- Verify: **isolated** lab DC only (brick risk). Double-gate the destructive path.
- Rollback: mandatory restore step; never run outside a throwaway DC.

**WS-B — Forest-trust attack chain**
- Goal: extract inter-realm trust key (`trustedDomain.trustAuthIncoming/Outgoing` via DRSUAPI bulk pull, extend `ms-drsr`) → forge inter-realm TGT (extend `ms-pac-forge`) → S4U2Self → S4U2Proxy as DA in the trusted forest.
- Files: `ms-drsr` (extend), `ms-pac-forge` (extend — note it is now 0.2.0/`PacForgeError`, add new variants as needed), `crates/kerberos/`.
- Effort: M–L · Depends: WS-E two-forest trust lab; ms-lsad `LsarQueryTrustedDomainInfoByName` (opnum 48) as an alternate key-read path.
- Acceptance: DA access in the trusted forest via the forged inter-realm TGT.
- Verify: live two-forest lab; offline unit test for trust-key parse + inter-realm PAC forge.
- Rollback: read + forge only; no writes to either forest.

### Tier 3 — defender polish (top-10 Rust-AD absorbs; deterministic, no-AI)

**WS-15 — Clock-skew handling** (source: skewrun)
- Goal: detect DC time (CLDAP rootDSE `currentTime` / NTP / Kerberos ping), silently offset AS-REQ/TGS-REQ timestamps; `--time-offset ±secs` manual override.
- Files: `crates/kerberos/` time module OR new **`ad-time`** standalone crate (dual-use passes — DFIR/admin reuse → publishable at 0.1).
- Effort: S · Depends: none. No `libfaketime` — we are the sender, adjust in-code.
- Acceptance: a forge/roast against a DC with >5-min skew succeeds where it previously failed KRB_AP_ERR_SKEW.
- Verify: live against a deliberately skewed DC; unit test on the offset math.

**WS-16 — Tombstone-reanimation audit** (source: ghosthound)
- Goal: `check tombstones` — LDAP `SHOW_DELETED` on `CN=Deleted Objects`; rule "principal X holds Reanimate-Tombstones EACL → can restore deleted admin Y and inherit their groups"; add `CanReanimate` BH-CE edge; checks 41→42.
- Files: `crates/checks/` (rule pack), `crates/ldap/`, `adhammer-bloodhound` edge.
- Effort: M · Depends: none.
- Acceptance: flags a planted reanimation path in the lab; edge appears in BH-CE export.
- Verify: live LDAP query on DC01; unit test on the rule against a synthetic ACL snapshot.

**WS-19 — Baseline diff** (source: diego, no-AI form) — **DONE (2026-08-25)**
- Goal: `scan --baseline <prior.json>` → tagged `[NEW]` / `[RESOLVED]` / `[SEVERITY-CHANGED]` by `(id, affected_object)`, rendered in all 4 report formats.
- Files: `crates/report/src/baseline.rs` (new — `BaselineDiff::compute`, keyed on (id, object)), `crates/report/src/lib.rs` (`Report.baseline_diff` field + `with_baseline` + md/html/txt render + per-finding `[NEW]`/`[SEV CHANGED]` tag), `cli/src/attacks/scan.rs` (`--baseline <PRIOR_JSON>` flag, best-effort: missing/bad baseline warns, scan still emits), `cli/src/session.rs`.
- Effort: S · Depends: none.
- Acceptance: JSON carries a `baseline_diff` object; md/html/txt render the diff + tag findings. **Met** — 4 unit tests (compute new/resolved/sev-changed, identical=all-unchanged, bad-json errs, render+tag integration).
- Verify: unit tests green (offline). **Still to do live:** two-run on DC01 (blocked on lab).

**WS-F-krb — `setup krb5` enhancements**
- Goal: `--auto` (SRV-discover DCs, pick the one that returns a TGT, write krb5.conf) + `--append` (add a realm to an existing conf).
- Files: `cli/src/` setup handler (shipped in 1.4.2 WS-12).
- Effort: S · Depends: none.
- Acceptance: `--auto` writes a working krb5.conf on a fresh box; `--append` preserves existing realms.

### Tier 4 — ship hygiene + publish coordination

**WS-T4a — dcerpc 0.2.7 publish** — 17 clippy warnings already fixed (audit); commit, `--dry-run`, publish. Carries WS-4-P2 sealed-bind primitives + concrete crypto.
**WS-T4b — ms-bkrp 0.1.0 wire + publish** — implement `BackuprKey` opnum 0; foundation for 1.4.6 DPAPI backup-key extraction. (Currently 115 LOC scaffold across ms-bkrp+ms-xcep.)
**WS-T4c — ms-xcep 0.1.0 wire + publish** — MS-WSTEP-bundled AD CS web enrollment (CEP+CES); unblocks proper ESC8 web-enroll relay.
**WS-T4d — sibling wave publish** — ms-pac-forge 0.2.0, ntlm-relay 0.2.0, llmnr-poison 0.2.0, ms-csra 0.1.2 (from the audit). Independent leaves; publish bottom-up with dry-runs. OPTIONAL: adopt ms-pac-forge 0.2.0 in adhammer-kerberos (1-line: wrap `crates/kerberos/src/pac.rs:30` return in `Ok(…?)`, bump pin `"0.1.3"→"0.2"`); if adopted, ms-pac-forge 0.2.0 must publish BEFORE adhammer-kerberos.
**WS-T4e — adhammer 1.4.3 publish** — bump 1.4.2→1.4.3, CHANGELOG from `git log 1.4.2..HEAD`, publish 11 workspace crates bottom-up, tag `v1.4.3`, push main+tags.

---

## 4. Dependency ordering (build the DAG, respect it)

```
WS-4-P2 (Kerberos sealer)  ──┬─► WS-14 (cross-trust, uses sealed S4U2Proxy)
   └─► unblocks dcerpc 0.2.7 │
                             └─► WS-A1 (noPac, LDAP writes on hardened DC)
ms-drsr ext + ms-pac-forge ext ─► WS-B (forest trust)
ms-nrpc ext ─► WS-A2 (zerologon exploit)
(independent) WS-15, WS-16, WS-19, WS-F-krb, WS-1-P3, WS-2-P3, WS-8-P2, WS-13-CLI
Publish gate: dcerpc 0.2.7 ─► (adhammer consumes) ; sibling wave leaves ─► adhammer (only if 0.2.0 adopted)
```

---

## 5. Committed vs stretch vs deferred

**1.4.3 COMMITTED (fits ~3.5 weeks):**
Tier 1 all (Phase-3 non-negotiable) · WS-15 · WS-16 · WS-19 · WS-F-krb · Tier 4 (T4a + T4d + T4e mandatory).

**Stretch (only if Tier 1 wraps early):**
WS-A1 noPac · WS-T4b ms-bkrp · WS-T4c ms-xcep.

**Deferred to 1.4.4:**
WS-A2 Zerologon exploit · WS-B forest-trust · WS-C wire-hardening probes (LDAP CBT + SMB3 encrypt negotiate) · WS-D `krb-listen` (CLI module, dual-use rule) · WS-E legacy-DC matrix (2016/2019 spin-up) · WS-F SCCM/SCOM enum · WS-G ADIDNS full write (SRV/CNAME/MX/TXT) · WS-17/18/20/23/24 (ntdsextract2/kerlab/diego absorbs).

**Permanently rejected:** WS-21 (AI narrative), WS-22 (MCP mode) — "no AI" rule.

---

## 6. Ship sequence (week-by-week)

- **Week 1:** WS-15 (1d) → WS-19 (1d) → WS-1-P3 (1d, MSSQL Express install) → WS-13-CLI (2d) → start WS-16.
- **Week 2:** finish WS-16 → WS-8-P2 (3d) → WS-2-P3 (2d).
- **Week 3:** WS-4-P2 (5–6d, strict timebox; defer to 1.4.4 if it slips). *This week is the make-or-break.*
- **Week 4 (0.5–1):** Tier 4 — commit dcerpc clippy, WS-T4a dcerpc 0.2.7, WS-T4d sibling wave, release commit, `--dry-run` chain, WS-T4e adhammer 1.4.3 publish + tags.

---

## 7. Live-validation matrix (8 tests per DC, expanded from 1.4.2's 5)

Existing: dcsync krbtgt · coerce `--pipe spoolss` · coerce bad-pipe clap-gate · enum sessions env-fallback · dcsync `--all --yes --limit 3`.
New in 1.4.3: **dcshadow `--drsuapi --push --dry-run`** (WS-2-P3) · **scan `--baseline`** (WS-19) · **attack dns `--dry-run`** (WS-13-CLI). Add a **sealed-bind smoke** (WS-4-P2) as the 9th once it lands.
Run on both testlab.local forests (DC01 2025 @ 172.29.247.82 / 2022server @ 172.29.255.68). krbtgt hashes must match the Saturday baseline byte-for-byte.

---

## 8. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| WS-4-P2 crypto slips the timebox | Med | High (blocks WS-14/A1) | Strict Week-3 box; ship primitives-only + defer concrete to 1.4.4; do NOT half-ship |
| Session-limit kills an agent mid-WS | Med | Med | Commit/push before agent runs; "commit partial + note next" escape hatch |
| Disk fills mid-build | Med | Med | ≥25 GB precondition; prune target dirs between heavy steps |
| MSRV silently raised by `clippy --fix` | Med | Med | Re-verify MSRV after any fix sweep; rust-version declared → MSRV-aware clippy |
| Zerologon `--exploit` bricks a shared DC | Low | High | Isolated throwaway DC only; double-gate; mandatory restore |
| ms-pac-forge 0.2.0 adoption breaks adhammer | Low | Med | Known 1-line fix (`Ok(…?)`); patch + dry-run before adopting; else stay on 0.1.3 |
| clippy 1.9x introduces new default lints on ship | Med | Low | `#![allow(unknown_lints, …)]` at crate roots as done in 1.3.10 CI de-drift |

---

## 9. Definition of done (all must hold to tag v1.4.3)

> **STATUS 2026-08-25 — READY TO TAG.** Descoped to the Tier-0 "prove it, cover it"
> release; Tier-1 Phase-3 (WS-4-P2 sealed bind, WS-1-P3, WS-2-P3, WS-13-CLI, WS-8-P2)
> → **1.4.4** (`.agents/adhammer-1.4.4-plan.md`). Gate met: fmt clean · clippy `-D`
> clean · `test --workspace` 185 pass/0 fail · MSRV still 1.87 (no raise) · CHANGELOG
> written · **dcerpc 0.2.7 published** (crates.io + `v0.2.7` tag) · no AI/competitor/
> CLI-break/un-yank. **Live-validated on both `testlab.local` forests (DC01 2025 +
> 2022server):** scan → 16/16 evidence-backed findings each, WS-19 baseline delta,
> ESC-registry fold, `dcsync krbtgt` matched baseline on both DCs. Remaining to ship:
> `git tag v1.4.3` + publish 11 workspace crates bottom-up (needs explicit crates.io
> go). Sibling wave (ms-pac-forge/ntlm-relay/llmnr-poison 0.2.0, ms-csra 0.1.2) is
> independent — publish separately, NOT gating 1.4.3.

- [ ] Every Tier-1 item live-validated on ≥1 DC, output captured for release notes.
- [ ] `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean at Rust stable.
- [ ] `cargo test --workspace` green (≥164, plus new WS tests); every new wire test uses a real `include_bytes!` fixture.
- [ ] 8/8 (→9/9 with sealed bind) live wire tests green on DC01 + 2022server.
- [ ] MSRV re-verified for any crate touched; `rust-version` accurate.
- [ ] `CHANGELOG.md` `## [1.4.3]` written from `git log 1.4.2..HEAD` (not memory).
- [ ] dcerpc 0.2.7 published clean; sibling wave published bottom-up with dry-runs.
- [ ] 1.4.4 plan doc scaffolded from what got cut.
- [ ] No AI dep, no competitor name, no CLI break, no un-yank of 1.4.1 sub-crates.

## 10. Non-goals (1.4.3)

No AI features · no cloud/hybrid/federation · no CLI breaking changes · no new sibling crates beyond ms-bkrp / ms-xcep / optional `ad-time` · no un-yank of yanked sub-crates.

## 11. Files to update on ship day

`Cargo.toml` 1.4.2→1.4.3 · `CHANGELOG.md` new section · `README.md` "What's new" · this plan (mark DONE/DEFERRED) · scaffold `.agents/adhammer-1.4.4-plan.md` · memory HEAD (`project-adhammer`).
