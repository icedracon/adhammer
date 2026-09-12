# ADhammer 1.5.1 — Pre-Review (W151-06 preflight)

**Status:** planning-only assessment of the current worktree deltas against
PLAN_1.5.1.md §W151-06 (package/deps/release gate). Not a release approval.
Not a candidate lock. All findings feed the eventual W151-06 gate; nothing
here changes source, deps, versions, or history.

**Baseline:** `main` at `87ac44be410a65611f816b62f516d204ee025579` + dirty
worktree + 8 untracked files (see METHOD_CATALOG_1.5.1.md §6 for the file
list). Toolchain: rustc 1.88 (workspace MSRV), Windows dev profile.

## 1. Compile-gate status (local, dirty tree)

| Gate | Result | Notes |
|---|---|---|
| `cargo build -p adhammer --locked --offline` | ✅ PASS | 0.59s incremental |
| `cargo clippy -p adhammer --locked --offline --no-deps` | ✅ PASS | Clean walk of 9 workspace crates + adhammer bin |
| `cargo fmt --check` | not-run | Owed |
| `cargo test --workspace` | not-run | Owed |
| `cargo build --workspace --all-features` | not-run | Owed — MUST check `mssql` feature builds cleanly |
| `cargo build --workspace --no-default-features` | not-run | Owed |
| `cargo deny check advisories` | not-run | Owed |
| `cargo deny check licenses` | not-run | Owed |
| `cargo deny check sources` | not-run | Owed |
| `cargo audit` | not-run | Owed (dated freshness matters) |
| Strict rustdoc build | not-run | Owed |

**Blocker resolution:** the seven `not-run` gates each need a dedicated run.
Some (`fmt --check`, `test --workspace`) are fast + local; others (`deny`,
`audit`) need advisory-DB freshness ≤ 24 h and are owed for the candidate
commit, not for planning.

## 2. Dependency delta — `p12 = "0.6"`

**Added in worktree:** `cli/Cargo.toml` line 96-104 → `p12 = "0.6"` under
adhammer bin only. **Not** added to any of the 11 library crates.

**Transitive tree (from `cargo tree -p adhammer --edges normal -i p12`):**

```
p12 v0.6.3
└── adhammer v1.5.1 (cli/)
```

Single ancestor = the binary crate. Pulls: `des`, `rc2`, `md-5`, `sha1`,
`hmac`, `pbkdf2`. All RustCrypto lineage, MIT/Apache-2.0, small, single-purpose.

| Sub-question | Assessment |
|---|---|
| License compatibility | MIT/Apache-2.0 dual — matches every other RustCrypto dep already in tree. No new license surface. |
| Advisories | `cargo audit` not-run; `p12 0.6.3` published 2024; RustCrypto lineage → historically responsive. Owed check. |
| Reachability from library crates | ZERO. All library manifests untouched. |
| Public-API surface | ZERO. p12 types never appear in a `pub` signature. Only used inside `attacks::kerb::pkinit` and `attacks::ldap::auth` for local PFX decode. |
| Feature-set impact | Silently activates `des`, `rc2` (both were absent). No conflicting features observed. |
| `--all-features` build | Not verified this session. |
| `--no-default-features` build | Not verified this session. |
| Binary-size impact | Not measured. Typical p12 tree adds ~50-80 KB. |
| Compile-time impact | Not measured; RustCrypto deps are cheap. |
| SemVer impact | **PATCH-safe**. Library crates unchanged → 1.5.0 → 1.5.1 correct per [[feedback-semver-minimum-bump]]. |
| Alternative | Hand-rolling PKCS#12 = ~400 LOC (ASN.1 SEQUENCE walk + PBE decrypt). Feasible but weighs against per [[feedback-stier-minimalism]]. p12 is a widely-used minimal parser; net verdict = accept. |

**Verdict:** dep addition is **safe** for a patch bump. Owed: license notice
row in the released package's `THIRD_PARTY_LICENSES` (if that file exists in
the project — needs verification for W151-06). Owed: `cargo audit --deny warnings`
freshness check before publish.

## 3. Library-crate SemVer envelope

**`git diff --stat crates/` returns empty. `git status --short crates/` empty.**

All 11 library crates (`adhammer-core`, `adhammer-sdk`, `adhammer-collector`,
`adhammer-checks`, `adhammer-graph`, `adhammer-kerberos`, `adhammer-report`,
`adhammer-sysvol`, `adhammer-ldap`, `adhammer-bloodhound`, `adhammer-secrets`)
are **pristine** relative to `origin/main`. This is exactly the SemVer
posture PLAN_1.5.1 asks for: a **patch bump** that changes no library API.

Consequence: workspace `version = "1.5.1"` bump in root Cargo.toml propagates
to every library pin, but with no signature or behavior changes across
`pub fn` / `pub struct` / `pub trait` surface. Safe.

Cross-check owed before publish: `git show origin/main..HEAD -- 'crates/**/*.rs' | grep -E '^[+-]\s*pub '`
should return **empty** for library crates (verify signature stability).

## 4. Untracked implementation files — landing decision

Eight untracked files sit in the worktree, wired into `main.rs` dispatch but
uncommitted:

| File | Wired into | Recommended action |
|---|---|---|
| `cli/src/attacks/kerb.rs`        | `Command::Kerb`  | **Land.** Full four-variant `KerbCmd`. Two of four are scaffolds — see §5. |
| `cli/src/attacks/creds.rs`       | `Command::Creds` | **Land.** `creds gpp-decrypt` (F6) is complete and calls existing `adhammer_sysvol::gpp::decrypt_cpassword`. |
| `cli/src/attacks/ldap.rs`        | `Command::Ldap`  | **Land.** `ldap auth` (F1b) SASL EXTERNAL bind. Bind-test only — must be labeled as such. |
| `cli/src/attacks/lsa_offline.rs` | `Command::Lsa`   | **Land + label as SCAFFOLDING.** MDMP outer reader only; symbol walk deferred. See §5. |
| `cli/src/typed_json.rs`          | direct use in emitters | **Land.** First-wave typed JSON — this is exactly what W151-02 needs to extend. |
| `cli/src/gap_hint.rs`            | direct use at gap sites | **Land + doc note in CONTRIBUTING.** See §6. |
| `docs/GAPS.md`                   | `Command::Gaps` handler | **Land.** External-tool swap-in list; paired with `gap_hint.rs`. |
| `scripts/scratchpad-bootstrap.sh`| none              | **Do NOT land.** Session helper for another live-DC target — off-lane per [[project-adhammer]] HEAD. Move to your scratchpad or remove. |

## 5. Scaffolding-honesty deficit

**Precedent (1.4.7):** `check krb-seal` sealed REQUEST path was labeled
`[SCAFFOLDING]` in help text and `hide_from_help` because the wire layout
wasn't finalized. Same pattern is missing here:

| Verb | Actual state | Current help text | Fix needed |
|---|---|---|---|
| `kerb trust-mint`      | Wrapper over `attack asktgt` — works when caller supplies the trust key | Says so | ✅ Honest already |
| `kerb trust-dump`      | **Blocked on `ms-lsad v0.3` — `LsarRetrievePrivateData` not yet published** | Says "blocked on ms-lsad v0.3" in inline comment | ✏️ Add `[SCAFFOLDING]` prefix to CLI `///` doc + consider `hide_from_help` until ms-lsad v0.3 publishes |
| `lsa lsass-parse`      | **Scaffold only — outer MDMP directory reader; per-Windows-build symbol walk deferred** | Says "scaffold" in module doc but the CLI `///` line reads user-facing | ✏️ Add `[SCAFFOLDING]` prefix + emit a very visible runtime banner (like `check krb-seal` did) explaining what it actually parses vs what pypykatz would |
| `attack icpr-esc1`     | Offline preflight — sealed pipe not wired | Says "not wired in this build" | ✅ Honest already |

**Two edits owed** (both live in the untracked files, so no history rewrite):
`cli/src/attacks/kerb.rs::KerbCmd::TrustDump` and
`cli/src/attacks/lsa_offline.rs::LsaCmd::LsassParse`.

Estimated fix: 20 min. Should land **before** the untracked files are
committed, not as a follow-up commit.

## 6. Hard-rule sweep

| Rule | Result | Detail |
|---|---|---|
| [[feedback-never-leak-lab-identifiers]] | ✅ PASS | grep across all 8 untracked files + 7 modified files against `.githooks/leak-terms.txt` (tracked patterns) + `.githooks/leak-terms.local.txt` (local literal secrets): zero hits. |
| [[feedback-adhammer-no-cloud-ever]] | ✅ PASS | No Azure / Entra / AAD / AD-FS / vSphere references in new files. |
| [[feedback-adhammer-hard-rules]] (no AI) | ✅ PASS | No embeddings / LLM / model / classifier vocabulary. |
| [[feedback-no-competitor-mentions]] | ⚠️ **SCOPE CLARIFICATION** — see below |
| [[feedback-stier-minimalism]] | ✅ ACCEPT | `p12 = 0.6` is a widely-used minimal parser; alternative = ~400 LOC hand-roll. RustCrypto lineage matches the ripgrep-scale bar. |
| [[feedback-semver-minimum-bump]] | ✅ PASS | Library crates untouched → PATCH (1.5.0 → 1.5.1) correct. |
| [[feedback-ship-workflow]] | ✅ N/A this pass | (No `git add`, `git commit`, `git push`, or `cargo publish` in scope for pre-review.) |
| [[feedback-never-push-without-asking]] | ✅ N/A this pass | Same — nothing being pushed. |
| [[feedback-kali-vbox-always-test]] | 🟡 OWED | Must exercise the four new verbs (`kerb pkinit`, `kerb u2u-nt`, `creds gpp-decrypt`, `ldap auth`, `lsa lsass-parse`) on Kali VBox real PTY before the candidate ships. |
| [[feedback-ux-test-discipline]] | 🟡 OWED | Same PTY receipt required for the two new menu rows (`KerbPkinit`, `KerbU2uNt`, `GppDecrypt`) — cold-newcomer sit-down. |

### 6.1 [[feedback-no-competitor-mentions]] — scope clarification

`cli/src/gap_hint.rs` names external tools (`impacket`, `Certipy`, `pypykatz`,
`Rubeus`, `rusthound-ce`, `SharpHound`) as **operator-facing swap-in
suggestions at coverage gap sites**. Line 4 of that file explicitly states
"1.5.1 close review, user-directed", meaning this pattern was authored under
user approval.

The **memory rule** reads (verbatim):
> never name impacket/PingCastle/mimikatz/BloodHound/etc. in posts or
> READMEs; pitch our tools by what THEY do, not vs others

**Purposive analysis:**

- The rule targets **competitive pitching** ("vs others") in **marketing
  surfaces** (posts + READMEs).
- `gap_hint.rs` does the **opposite** of a competitive pitch: it says
  "adhammer does not cover this — use the specialist tool `X` with your
  captured params substituted in".
- PLAN_1.5.1.md §CEO already reconciles the two: "Не обещать паритет с
  Impacket/Rubeus/Mimikatz без сравнительных доказательств" — do not
  *claim parity* without evidence. Naming a specialist to hand off to is
  the opposite of a parity claim; it is a **humility marker**.

**Recommendation:** land `gap_hint.rs` + `docs/GAPS.md` as-is, but add a
CONTRIBUTING.md section (or `docs/POLICY.md` if it exists) titled
"External-tool references — scope of the no-competitor-mentions rule"
that documents this distinction. This keeps future contributors from
either (a) removing the honest gap hints or (b) introducing genuinely
competitive pitching under this precedent.

**Owner sign-off requested:** user should confirm the purposive read before
this actually ships. Not a stop, but a decision to record.

## 7. What this pre-review does NOT do

- Does not commit anything.
- Does not run `cargo publish --dry-run`.
- Does not touch tags or origin.
- Does not run live-DC tests.
- Does not resolve open decisions in PLAN_1.5.1.md (distribution mode,
  supported OS/auth matrix, executors, JSON migration contract) — those
  are user calls, not pre-review calls.

## 8. Verdict summary

The 1.5.1 candidate is **~85% ready** on the automatic gates, gated by
five items ordered by cost-to-clear:

1. Add `[SCAFFOLDING]` label + `hide_from_help` to `lsa lsass-parse` and
   `kerb trust-dump`. (20 min, no history impact — untracked files.)
2. Delete `scripts/scratchpad-bootstrap.sh` from worktree (off-lane).
3. Add CONTRIBUTING.md § on the gap-hint / no-competitor-mentions scope
   distinction. (10 min prose.)
4. Run the remaining seven automatic gates: `fmt --check`, `test --workspace`,
   `build --workspace --all-features`, `build --workspace --no-default-features`,
   `deny check advisories/licenses/sources`, `audit`, strict rustdoc.
5. Two live-PTY receipts: cold-newcomer drive of the interactive menu on
   Kali VBox + a CLI cold-run of the new verbs. Per [[feedback-ux-test-discipline]]
   this is not optional for UX-affecting changes; it produces the ship receipt.

None of these five are blockers to keep working on W151-02..05. They are
blockers **only** to declaring the candidate ready for the release-gate
authorization step (which is separate from this planning task).
