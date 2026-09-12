# ADhammer 1.5.1 — Result / Error / JSON Contract (W151-02)

**Status:** specification. Documents the current shape, names the gaps, and
proposes the envelope + status vocabulary the release wants to converge to.
No source changes in this pass. Every proposal below is a design contract
consumers can compile against; the actual code changes land under the
individual F-B* / F-C* work items already sketched in the recent commit
history (F-B4 is the first-wave typed-JSON that this doc extends).

## 1. Ground truth today

### 1.1 The two envelope shapes in flight

Both live in `cli/src/main.rs::dispatch_json`
(`87ac44be`) + `cli/src/typed_json.rs` (untracked).

**A. Fallback envelope — `adhammer_core::AttackResult`** (60 of 63 dispatched
verbs today):

```jsonc
{
  "command": "adhammer attack coerce",   // full invocation label
  "success": true,                        // POSIX exit-status boolean
  "evidence": "…text-blob…",              // stdout+stderr merged
  "finding_id": null                       // rare; set only when the verb minted a Finding
}
```

**B. Typed envelope — `TypedResult`** (3 verbs: `attack roast`, `attack laps`,
`attack gmsa`):

```jsonc
{
  "command": "adhammer attack roast",
  "success": true,
  "typed": {                              // Structured{kind, …}
    "kind": "roast",
    "kerberoastable": [ { "sam": "svc_sql", "spn": "MSSQL/db.corp.local", "hash": null } ],
    "asrep_roastable": [],
    "hashglass_hints": [ { "mode": 13100, "name": "TGS-REP etype 23", "confidence": 0.98 } ]
  },
  "evidence": "…text-blob…"               // duplicate of the same stdout — kept for consumer compat
}
```

**C. Inert `--json` on report verbs** — `scan` / `auto` / `check` / `setup` /
`run` / `doctor` / `gaps` **ignore** `--json`. `warn_inert_output_flags` prints
a `note:` on stderr and dispatches human-report code paths. No JSON.

### 1.2 The status vocabulary today

`adhammer_core::FindingStatus` (crates/core/src/scope.rs:217) is the finding-
level vocabulary:

```
Found · NotFound · Blocked · NotApplicable · Error
```

**No parallel action-result vocabulary exists.** `AttackResult.success` is a
raw boolean. Interactive dispatch collapses to green ✓ / red ✗ off
`Result<(), anyhow::Error>`. There is no "partial", "cancelled", "access-
denied", "unsupported", "transport-error", or "confirmed-with-effect"
concept anywhere in the pipeline.

### 1.3 Exit codes

`dispatch_json` returns `Ok(())` on success and `anyhow::bail!` on non-zero
child status → the process exits 1. **No distinction between fatal bug,
access denied, transport error, or partial completion.** Machine consumers
cannot script differential handling from the exit code.

## 2. Gaps identified for W151-02

Numbered per PLAN_1.5.1 §W151-02 must-be-true statements:

### G-1. Status vocabulary too coarse

**Plan requires:** "Отделить техническое завершение, подтверждённый результат,
partial, отказ в правах, unsupported, отмену и ошибку. Очистка не теряется в
общем status."

**Gap:** `success: true|false` cannot encode any of these.

### G-2. Completed-but-required-stage-errored is silently a success

**Plan requires:** "Не делать завершённую операцию успешной при ошибке
обязательного этапа."

**Gap:** every verb that runs multiple stages (e.g. `attack esc1` — enroll →
retrieve → PtT → verify) currently returns `success: true` if the *last*
stage returned Ok, ignoring earlier failures whose output was best-effort
salvaged.

### G-3. No schema version

**Plan requires:** "Версионировать structured schema; сохранить документиро-
ванный переход для старых consumers."

**Gap:** neither envelope carries a version field. A machine consumer today
cannot tell "am I looking at v1 blob" from "am I looking at v2 typed" beyond
sniffing for the presence of the `typed` key.

### G-4. Silent empty-JSON on text parser failure

**Plan requires:** "Нет молчаливого пустого JSON при ошибке text parser."

**Gap:** `try_structured` returns `None` on parse failure and the code falls
to the untyped envelope — silently. A consumer of `attack roast --json`
expecting the typed payload sees a blob and cannot distinguish "the child
crashed pre-output" from "parser didn't match a valid new output shape".

### G-5. Progress-on-stderr / data-on-stdout not enforced

**Plan requires:** "Прогресс на stderr, данные на stdout."

**Gap:** `attack roast --text` prints `== Kerberoastable (N) ==` section
headers on stdout — decoration, not data. Every verb has its own mix.
Typed-JSON parsers work around this by skipping non-data lines; a machine
consumer of `--text` still has to.

### G-6. Progress accumulates in JSON wrapper

**Plan requires:** "накопление вывода в JSON wrapper ограничено."

**Gap:** `dispatch_json` captures the child's full stdout+stderr into
`evidence: String`. Unbounded. A verb that emits 500 MB (e.g. deep scan
against a large domain) → 500 MB `evidence` field in the JSON.

### G-7. Interactive/CLI/HTML render divergence

**Plan requires:** "одинаковые входы дают согласованные статусы CLI/menu/
JSON/HTML."

**Gap:** interactive shows "done" / "failed" without qualifiers; CLI text
shows verb-specific status lines; JSON `AttackResult` says success bool;
HTML report doesn't distinguish `Blocked` from `Error` findings in its
top-of-page banner. **Four surfaces, four vocabularies.**

### G-8. Typed-JSON coverage 3/63

**Plan does not require full coverage in 1.5.1** — F-B4 explicitly staged as
a first wave. But the gap is stark: 60 verbs pass through text-blob evidence
today. The five high-value non-typed verbs are `attack dcsync`, `attack
secretsdump`, `attack samr`, `enum samr`, and `enum posture`.

### G-9. No `--json` on the seven report verbs

**Deliberate today.** `scan`, `auto`, `check`, `run`, `doctor`, `gaps`,
`setup` produce reports, not action results. Plan does not want this to
change silently. But `run --json` **does** emit structured JSON (see
`blackbox::run_json_string`). Inconsistency: some report verbs have their
own JSON path, others reject the flag.

## 3. Proposed contract — `EnvelopeV2`

Additive to what ships today. `V1` (`AttackResult` + typed
`Structured` variants) stays as the default output until the next MINOR bump.
Consumers opt-in to `V2` via `ADHAMMER_JSON_ENVELOPE=v2` **or** the `--json-v2`
flag (both proposed; not yet implemented).

```jsonc
{
  "schema_version": "2",
  "command": "adhammer attack roast",
  "status": "confirmed",                  // 7-value action-result vocabulary (§4)
  "exit_class": "ok",                     // 7-value exit-class vocabulary (§5)
  "typed": {                              // typed body per verb; verb dispatcher decides shape
    "kind": "roast",
    "…" : "…"
  },
  "typed_extraction": "ok",               // "ok" | "unrecognised" | "verb-not-supported"
  "finding_id": null,                     // optional link into report.json findings[] by id
  "wire_exchanges": [                     // optional; only when captured with -vv or --wire-log
    { "layer": "kerberos", "direction": "sent", "opnum": null, "bytes": 174 }
  ],
  "diagnostics": {                        // optional; failure diag when status ≠ confirmed/ok
    "category": "access-denied",           // matches status (§4)
    "code": "kdc-error-1765328378",       // stable machine code
    "message": "KDC_ERR_C_PRINCIPAL_UNKNOWN",  // human summary
    "hint": "check user spelling; enum krb-users to enumerate names"
  },
  "evidence_ref": {                       // pointer, not a blob
    "stdout_bytes": 4123,
    "stderr_bytes": 189,
    "stdout_sha256": "abc…",
    "stderr_sha256": "def…"
  }
}
```

**Rationales:**

- `schema_version` addresses G-3.
- `status` + `exit_class` addresses G-1, G-2, G-4, G-7.
- `typed_extraction` addresses G-4 explicitly (a consumer sees when we
  *tried* to type but couldn't).
- `evidence_ref` addresses G-6 by replacing the unbounded blob with a
  bounded 32-byte content-hash pair; the raw text is written to an out-dir
  file when the operator passes `--stash-evidence <dir>`.
- Every field except `command` / `status` / `schema_version` is optional
  → consumers can strip payload for minimal renders.

`V1` never disappears in a patch release. The V1→V2 flip default becomes
part of the next minor (SemVer discipline per [[feedback-semver-minimum-bump]]).

## 4. Action-result status vocabulary

Seven values, all mutually exclusive:

| status | Meaning | Exit-class default |
|---|---|---|
| `confirmed`      | The verb ran, produced its intended effect, and (where applicable) the effect was verified. Ex: `dcsync krbtgt` returned all replicated blobs; `attack esc1` retrieved the cert and validated it via a follow-up bind. | `ok` |
| `completed`      | The verb ran, produced output, but the "verify" stage was skipped or not applicable. Data is present; freshness / correctness not re-checked. Ex: `enum samr` returned rows but did not re-validate against a second collection. | `ok` |
| `partial`        | Some stages succeeded, some failed. Salvageable rows are in `typed`; failed stages are enumerated in `diagnostics.stages[]`. Ex: `attack secretsdump` decoded SYSTEM+SAM but SECURITY was AccessDenied. | `partial` |
| `access-denied`  | Auth failed at the target's boundary. Not our fault. Ex: `attack laps` couldn't read `msLAPS-Password` for principal X. | `access-denied` |
| `unsupported`    | Target does not implement the wire path we tried. Ex: `attack dcshadow` LDAP path against Server 2019+ ("system-owned attribute" block). | `unsupported` |
| `cancelled`      | User interrupted mid-flight (Ctrl-C, TERM). Partial output retained where safely written. | `cancelled` |
| `error`          | Bug in our code, unexpected protocol answer, or transport-layer break. Includes panics recovered by the outer catch. | `bug` (2) / `transport` (3) — see §5 |

**Interactive rendering:** confirmed → green ✓; completed → cyan ✓ (no verify);
partial → yellow ~; access-denied/unsupported/cancelled → grey slash; error → red ✗.
Text/HTML render maps 1:1. No colour-only distinction ([[feedback-hard-critic-and-focus]] wants text-primary UI signals).

## 5. Exit-code vocabulary

`AttackResultStatus` → exit code:

| exit-class | code | Meaning |
|---|---|---|
| `ok`             | 0   | confirmed or completed |
| `partial`        | 1   | partial |
| `access-denied`  | 2   | access-denied |
| `unsupported`    | 3   | unsupported |
| `cancelled`      | 130 | cancelled (matches POSIX SIGINT) |
| `bug`            | 64  | error caused by our code (EX_USAGE analog; > standard `1`) |
| `transport`      | 65  | error caused by network/target break (EX_DATAERR analog) |

Machine consumers can `if [ $? -eq 2 ]; then …` differentially.

The plan explicitly allows patch versions to reshape non-guarantee semantics
(exit codes in adhammer are not documented as a stable API — check
`docs/STABILITY.md` before committing to this).

## 6. Migration story

- **Patch (1.5.1):** ship the `AttackResultStatus` enum in `adhammer_core`
  as `pub` behind `#[non_exhaustive]`; keep every existing handler emitting
  V1 blobs. Only the SDK's compile-time API changes — nothing new appears
  on the wire.
- **Patch or minor (1.5.2 or 1.6):** wire the `--json-v2` opt-in flag +
  `ADHAMMER_JSON_ENVELOPE` env; every handler starts emitting either shape
  based on the flag. Documented in `docs/STABILITY.md` as "V2 available,
  V1 still default".
- **Minor (1.6 or 2.0):** default-flip. Old consumers set
  `ADHAMMER_JSON_ENVELOPE=v1` to keep the old payload for one more line.
- **Major (2.x):** V1 removed. `AttackResult` struct kept for internal use,
  no longer serialised to the wire.

**Non-goal:** patch 1.5.1 does NOT flip defaults, does NOT change the
current wire output, does NOT rev the SDK MAJOR. All contract additions
are additive + gated behind an env/flag.

## 7. Coverage-expansion queue (F-B4 continuation)

Priority order (biggest-payoff-first). Each row is a follow-up patch, not a
1.5.1 blocker:

| Verb | Reason to type | Estimated LOC |
|---|---|---|
| `attack dcsync`      | Emits ≥ 5 keys per principal (NT + AES128 + AES256 + AES256-SHA1 + optional AES256-SHA384) → highest-value payload in tree | ~120 |
| `attack secretsdump` | SAM + LSA-secrets + cache — multi-section, currently a flat text blob | ~180 |
| `attack samr` / `enum samr` | Domain user list — table today, obvious rows-in-Vec | ~60 |
| `enum posture`       | 2-8 posture findings per DC, currently one-line-per-check | ~50 |
| `attack coerce`      | Currently returns a coerced-auth witness; typing pairs it with the `capture` output | ~40 |
| `attack unpac`       | NT hash + user + realm — trivial | ~30 |
| `attack asktgt`      | ccache path + etype + expires | ~40 |

## 8. Test-evidence spec (per PLAN §W151-02)

The plan mandates: "synthetic success/failure/partial/cancel/non-TTY/large-
output cases, JSON schema fixtures, SDK consumer compile".

Concrete test surfaces owed (not written in this pass):

1. **`crates/core/src/finding.rs::attack_result_v1_roundtrip`** — serde
   round-trip on `AttackResult` proves V1 stability across releases.
2. **`crates/core/src/finding.rs::envelope_v2_shape`** — JSON schema
   fixture matching §3.
3. **`cli/src/typed_json.rs::structured_extraction_status_labeled`** —
   verifies `typed_extraction` returns "unrecognised" (not silently
   missing) when a supported verb's text is unparseable.
4. **`cli/src/main.rs::cancel_signal_reports_cancelled_not_error`** —
   send SIGINT to a running child, expect `status: cancelled` and
   exit-code 130 (not 1).
5. **`cli/src/main.rs::partial_stage_failure_reports_partial`** — inject
   a stage failure mid-verb via a mock backend, expect
   `status: partial` and non-empty `diagnostics.stages[]`.
6. **`cli/src/main.rs::large_output_uses_evidence_ref_not_blob`** —
   run against a mock that emits > 1 MB stdout; expect
   `evidence_ref.stdout_bytes` + `stdout_sha256`, no blob in the JSON.
7. **`cli/src/main.rs::non_tty_still_prints_data_on_stdout`** —
   redirect stdout to file; the file receives only rows, no ANSI, no
   progress lines. Progress ends up in the stderr redirect.
8. **`cli/tests/sdk_consumer.rs`** — a tiny external crate under
   `crates/sdk/examples/consume-v1/` compiles against the released
   `adhammer_core::AttackResult` shape; a `consume-v2/` sibling does
   the same for V2. Both must build every release.

Tests 1-3 land inline with the enum-type addition (SDK-compile-only, no
wire change) → 1.5.1-safe.

Tests 4-7 need the flag/env wiring → 1.5.2 track.

Test 8 is the release gate for the V1→V2 flip decision.

## 9. Definition of done for W151-02

The plan's language: "одинаковые входы дают согласованные статусы CLI/menu/
JSON/HTML".

Minimum acceptance for the release cycle this document covers:

- [ ] `AttackResultStatus` enum lives in `adhammer_core`, `#[non_exhaustive]`.
- [ ] Every dispatched verb populates it, even if the current wire still
      emits V1 blob (SDK-visible only).
- [ ] Interactive dispatch uses the same enum for its ✓ / ~ / ✗ / grey
      rendering.
- [ ] Docs specify the V1→V2 migration story in `docs/STABILITY.md`.
- [ ] Two synthetic tests per §8 items 1-3 land.
- [ ] Zero silent behaviour change on the wire (V1 still default).

Everything else in this document is **backlog for later cycles**, not a
1.5.1 blocker.

## 10. Cross-references

- `docs/METHOD_CATALOG_1.5.1.md` §5 D-* — the CLI/menu drift rows also
  need to converge on this status vocabulary before menu-integration is
  W151-05-done.
- `docs/PRE_REVIEW_1.5.1.md` §5 — the scaffolding label discipline
  overlaps with `status: unsupported` (a scaffolded verb should
  emit `unsupported` on the paths it doesn't cover, not `error`).
- `docs/PLAN_1.5.2.md` §W152-04 — RustHound-CE integration must also
  produce a valid `EnvelopeV2` (or V1 blob) when it opens the ZIP;
  same partial/error/access-denied vocabulary applies.
