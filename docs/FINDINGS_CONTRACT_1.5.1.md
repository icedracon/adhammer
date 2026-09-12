# ADhammer 1.5.1 — Findings / Artifacts Contract (W151-04)

**Status:** spec + gap list. Documents the current finding shape, the report /
artifact writer behavior, and names the closable gaps. No source changes here.

## 1. Ground truth today

### 1.1 The `Finding` struct

`adhammer_core::Finding` (crates/core/src/finding.rs:216) carries:

- `id` (stable rule id — `P-KerberoastAdmin`, `A-Esc15-ms-crtd`, etc.)
- `title`, `category` (Passive/Active/Path/Info), `severity` (Info..Critical)
- `mitre[]`, `affected[]` (DNs/SIDs), `detail` (evidence-level string)
- `evidence[]` (WS-PROOF ground-truth artifacts, per-finding, verifiable by hand)
- `exchange[]` (WS-WPT wire transcripts — sent/recv frames with layer + opnum)
- `impact` (attack-chain narrative), `remediation`, `weight_bonus`
- `next_command()` derives copy-pasteable next verb w/ shell-safe substitution

### 1.2 `Report` + `CheckCoverage`

`adhammer_report::Report` (crates/report/src/lib.rs:154) aggregates:

- `findings[]`, `top_paths[]` (attack graph paths), `composite_chains[]`
- `coverage: Vec<CheckCoverage>` — every registry check row (tripped OR clean)
  with title / hypothetical_impact / remediation / mitre / control_areas /
  kill_chain_phase (WS-CTRLMAP: `ADP-01..30` taxonomy).
- Optional `baseline_diff` (WS-19), `bh_svg` (WS-BHG BloodHound-style graph)
- `is_clean_bill()` (WS-CLEAN-REPORT) — currently `findings.is_empty()`
- `content_hash()` — sha256 of canonical JSON for tamper-evidence

### 1.3 Sanitisation + rendering

- `sanitize_finding` (crates/report/src/lib.rs:25) — WS-OUTPUT-SANITIZE rewrites
  hostile-peer strings at aggregation time so `to_json` / `to_html` /
  `to_markdown` / `to_text_summary` never see raw remote input.
- Report has 4 renderers: JSON (canonical, deterministic), HTML (with SVG
  attack-graph + BloodHound-style principal graph), Markdown, TXT summary.
- HTML: WCAG-AA both themes, JS-optional (static SVG readable JS-off per WS-BHG).
- HTML content-hash footer + assurance banner (gated on `is_clean_bill()` AND
  non-empty coverage — the recent `14d4da9` fix makes zero-coverage render as
  "Inconclusive", not clean).

### 1.4 Secret artifacts

`crates/core/src/secret_write.rs::write_secret_artifact`:

- `create_new` mode — **fails loud if the target exists** (no silent overwrite).
- Unix: `0o600` mode at open.
- Windows: protected DACL (Owner + LocalSystem + BUILTIN\Administrators) applied
  at `CreateFileW` — the file never exists with a permissive inherited DACL.
- `f.sync_all()` before return.

## 2. Gaps identified for W151-04

Numbered per PLAN_1.5.1 §W151-04 mandates:

### G-4.1. Finding lacks `applicability` / `confidence` / `limitations`

**Plan requires:** "У находки есть источник, применимость, уверенность и
ограничения."

**Gap:** today's Finding has *source* (`evidence[]`) and *impact* but no
- `applicability` — under what conditions does this finding actually matter?
  (e.g. "ESC15 only exploitable when CA published Client Auth EKU AND the
  template EDITF_ATTRIBUTESUBJECTALTNAME2 is set")
- `confidence` — parametric: `Definite` (evidence proves the flaw) vs
  `Probable` (limited signals, needs field-verify) vs `Suspected` (heuristic)
- `limitations` — what would falsify this finding? What *wasn't* checked?

Proposed additive fields on `Finding` (each `#[serde(default,
skip_serializing_if = "Option::is_none")]` — patch-safe):

```rust
pub applicability: Option<String>,    // one-line qualifier
pub confidence: Confidence,           // enum Definite | Probable | Suspected
pub limitations: Option<String>,      // what would falsify this finding
```

### G-4.2. `is_clean_bill()` too eager

**Plan requires:** "no findings при неполном покрытии не превращается в clean
bill of health."

**Current guard:** `is_clean_bill = findings.is_empty()`. The HTML renderer
adds a secondary guard (assurance banner suppressed when
`coverage.iter().all(|c| c.findings == 0) && coverage.is_empty()`); the
`zero_coverage_is_inconclusive_not_clean_bill` test enforces the HTML
branch.

**Gap:** JSON `is_clean_bill()` still returns `true` on a zero-findings,
zero-coverage report. A machine consumer of `--format json` sees the flag
set and cannot tell "actually clean" from "scan blocked at bind". The
predicate should encode:

```
is_clean_bill = findings.is_empty()
                AND !coverage.is_empty()
                AND every collect-stage completed
```

The third clause needs collector-partial-completion state exposed on
`Report` (see G-4.3).

### G-4.3. Report has no `collection_completeness` field

**Plan requires:** distinguishing "absent / access-denied / transport-error /
malformed / partial" at the report level, not just at the check level.

**Gap:** if the collector paged 12 of 15 OUs and hit a per-entry timeout on
OU-13, the report today shows the findings it derived from OUs 1-12 and
nothing indicates OUs 13-15 were skipped. Result: potential false-clean on
the un-inspected slice.

Proposed additive `Report` field:

```rust
pub struct CollectionStatus {
    pub outcome: CollectionOutcome,  // Full | Partial | Failed
    pub errors: Vec<StageError>,     // per-stage error rows (kind, target, msg)
    pub coverage_note: String,       // human summary — "12/15 OUs, 3 timed out"
}
pub enum CollectionOutcome { Full, Partial, Failed }
pub enum StageError {
    AccessDenied { target: String, principal: String },
    TransportError { target: String, kind: String },
    MalformedResponse { target: String, note: String },
    Timeout { target: String, elapsed_s: u64 },
}
```

`is_clean_bill()` then requires `outcome == Full`.

### G-4.4. Interrupted-write leaves half-bundle

**Plan requires:** "Запись без молчаливого overwrite; незавершённый bundle не
выглядит завершённым."

**Current state:** `write_secret_artifact` uses `create_new` — fails-loud on
overwrite. **Good.** BUT it writes directly to the target path with no
tmpfile+rename atomic pattern. A killed process (SIGKILL, power loss)
between `f.write_all` and `f.sync_all` leaves a zero-length or truncated
file at the final path. Bundle write for the report (MD + HTML + JSON + TXT
sidecars) has the same problem — an interrupted write can leave a valid MD
next to a truncated HTML.

Proposed change:
1. `write_secret_artifact` writes to `<path>.part`, calls `sync_all()`, then
   `rename` to `<path>` (atomic on Unix; on Windows, use `MoveFileExW`).
2. Report bundle writer writes ALL sidecar files under `<out>.tmp.d/`, then
   renames the directory in one shot at the end.

Neither breaks the current SecretArtifact enum or the report writer signature.

### G-4.5. HTML JS-off graceful-degradation not tested

**Plan requires:** "HTML читается без JS…"

**Current state:** WS-BHG memory + comments say "Static SVG stays legible
with JS off". No test asserts this.

Proposed test in `crates/report/src/lib.rs`:

```rust
#[test]
fn html_readable_with_js_disabled() {
    let r = mk_report_with_findings_and_graph();
    let html = r.to_html();
    // JS-off browser drops <script> and never fires window.onload — but every
    // <text> label + <circle> node in the SVG must already have coords baked
    // in (no d3-force-simulation) and the initial-state DOM must render every
    // finding row and its details without a JS-enabled onclick handler.
    assert!(html.contains("<svg"));
    // Content readable at initial-DOM state (no `[hidden]`, no `display:none`
    // on required rows, no `.js-only` classes).
    assert!(!html.contains(r#"class="js-only""#));
    assert!(!html.contains(r#"style="display:none""#) || html.contains("<details"));
}
```

### G-4.6. Unicode + long-DN escaping not fixture-tested

**Plan requires:** "HTML читается без JS, выдерживает Unicode/длинные DN…"

Owed: a fixture-driven test that feeds `to_html` a Finding with:
- 1000-char DN
- mixed-script CN (Cyrillic + Arabic + Chinese)
- HTML-special chars in `detail` (`<script>`, `&`, `"`)

and asserts the emitted HTML never contains an unescaped `<script>` or
`<` sequence outside the pre-existing template.

### G-4.7. `attack laps --json` cleartext by default

**Plan requires:** "секреты не попадают в обычные журналы/отчёты по
умолчанию."

**Gap:** `attack laps` returns cleartext local-admin passwords on stdout
(and thus in `evidence` on the JSON envelope). No opt-in / opt-out.
Correct-by-design for the intended use case, but not aligned with the
plan's "default no secrets in output" guidance.

Proposed:
1. Default output: `<host>\t<account>\t<REDACTED>` on stdout; write
   cleartext only to a `--secret-out <dir>` path via `write_secret_artifact`.
2. Loud opt-in: `--reveal-passwords` flag surfaces cleartext on stdout
   (with a stderr banner: `warning: cleartext passwords in output — this
   run's stdout must be handled as sensitive`).

Same pattern applies to `attack gmsa`, `attack dcsync`, `attack
secretsdump`, `creds gpp-decrypt` (arguably the *point* of the verb — but
the stderr banner still applies).

### G-4.8. `--out-all` sidecar completeness not verified per-sidecar

**Plan requires:** distinguishing "partial output does not look complete".

`--out-all` (WS-OUT-ALL-STAGES, `89df4ee`) writes `.md`, `.html`, `.json`,
`.txt` sidecars. StageChecklist prints `✓ all-formats · <bytes> bytes`.
**No per-sidecar hash is emitted.** If one sidecar was truncated (see
G-4.4), the stage checklist still says ✓.

Proposed: extend StageChecklist with per-sidecar row:
```
✓ scan-report.md    54321 bytes  sha256:abcd…
✓ scan-report.html 128976 bytes  sha256:efgh…
✓ scan-report.json  32100 bytes  sha256:ijkl…
✓ scan-report.txt    5432 bytes  sha256:mnop…
```

## 3. Non-goals for 1.5.1

- **Full G-4.3 CollectionStatus** — additive but touches every collect
  path. Land the struct + enum in patch 1.5.1 (SDK-visible), wire only
  the most-obvious partial-completion paths (LDAP per-entry timeout,
  Kerberos AS-REQ failure) — full wiring 1.5.2+.
- **G-4.7 reveal-passwords flag rollout** — behavioural change for
  existing scripted consumers of `attack laps --json`. Announce for 1.5.2,
  flip default in a minor.
- **G-4.4 rename-atomic** — safe patch, but touches `write_secret_artifact`
  which is called from ≥ 5 attack paths. Lands in 1.5.1 as an internal
  refactor; every caller path re-tested.

## 4. What lands in 1.5.1 for W151-04

Minimum acceptance:

- [ ] G-4.1 — additive fields on `Finding` (`applicability`, `confidence`,
      `limitations`). Every existing rule that constructs a Finding still
      compiles (fields default to None / Confidence::Definite).
- [ ] G-4.2 — `is_clean_bill()` guard extended to require non-empty coverage
      AND `CollectionStatus::outcome == Full`.
- [ ] G-4.3 — `CollectionStatus` type + enum land in `adhammer_report`;
      `Report` gains `pub collection: CollectionStatus`. Field defaults to
      `Full` so old code compiles; obvious partial paths wired.
- [ ] G-4.4 — `write_secret_artifact` refactored to tmpfile+rename atomic.
- [ ] G-4.5 — `html_readable_with_js_disabled` test lands.
- [ ] G-4.6 — Unicode / long-DN / HTML-injection fixture test lands.
- [ ] G-4.8 — StageChecklist gains per-sidecar hash rows.

Non-blockers (backlog):
- G-4.7 reveal-passwords behavioural default flip.
- Full CollectionStatus wiring across every collector path.
- Confidence enum populated on every existing rule (initial batch =
  `Definite` everywhere; rule owners fine-tune later).

## 5. Cross-references

- `docs/RESULT_CONTRACT_1.5.1.md` §4 — `status: partial` at action-result
  level and `CollectionStatus::Partial` at report level share the same
  vocabulary; ensure the two enums are named consistently or one is a
  view of the other.
- `docs/METHOD_CATALOG_1.5.1.md` §5 D-5 — the `enum adcs` DnsArgs type
  reuse (potential functional bug) surfaces as an `is_clean_bill()`
  false-positive today; the G-4.3 wiring would flag it.
- `docs/CONN_CONTRACT_1.5.1.md` §3 — `status: cancelled` mid-flight
  should mark `CollectionStatus::Partial` with a Cancelled StageError,
  not silently drop the un-collected work.
- `docs/PRE_REVIEW_1.5.1.md` §5 — `lsa lsass-parse` scaffolding must
  emit `CollectionStatus::Partial` on the paths it doesn't cover
  (module import stream present, symbol walk deferred).
