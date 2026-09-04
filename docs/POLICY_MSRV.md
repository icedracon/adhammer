# ADhammer MSRV policy

**Status:** mandatory local policy.
**Authority:** `AGENTS.md` §5, `AI_RELEASE_GOVERNANCE.md` §4.1 (user-visible
compatibility decision requires rationale + test), `docs/POLICY_MSRV.md`
(this file).
**Enforced by:** `scripts/check_msrv_baseline.py` (fails CI on undeclared
MSRV drift) + the existing `msrv` job in `.github/workflows/ci.yml`.

## Baseline

The single source of truth for the currently supported MSRV is
`[workspace.package].rust-version` in the root `Cargo.toml`.

<!-- MSRV-BASELINE:1.88 -->

The comment above is the enforcement anchor. `scripts/check_msrv_baseline.py`
reads both values and fails if they disagree. Any commit that moves MSRV
must edit BOTH the manifest and this file in the same reviewed diff.

## Bump discipline — a user-visible compatibility decision

MSRV is not a maintenance detail. Every bump changes what Rust toolchains
compile ADhammer and its sibling ecosystem. Per `AI_RELEASE_GOVERNANCE.md`
§4.1 an MSRV increase is treated as a user-visible compatibility decision
with its own rationale and test.

### Required inputs before an MSRV move

1. **Rationale.** A one-paragraph note in the commit message + this file
   naming the specific language / stdlib feature or crate constraint that
   forces the bump. "Chore: bump MSRV" without a named driver is refused.
2. **Verification.** `cargo +<new-msrv> check --workspace --all-targets
   --locked` green locally + the CI `msrv` job green.
3. **Ecosystem awareness.** No transitive dep should require a *higher*
   MSRV than the new baseline. Verify with:
   ```sh
   cargo msrv verify --path .
   ```
   (or `cargo tree` + manual inspection when `cargo-msrv` is not installed).
4. **CHANGELOG entry.** MSRV moves land under the release's `### Changed`
   with the driver named.
5. **Update THIS file.** Change the `<!-- MSRV-BASELINE:X.Y -->` marker to
   the new baseline in the same commit.

### Cadence

- ADhammer follows the same "1-year cadence" as `windows-rs`, `tokio`, and
  `serde`: MSRV can move to a stable release that shipped **at least 6
  months ago**, and never to a version newer than that.
- We do **not** track `stable` unconditionally. Bumps are triggered by a
  concrete need, not by the fact that a newer stable exists.
- Emergency exception: an advisory fix that requires a newer MSRV bumps
  immediately. The rationale line names the RUSTSEC id.

### What triggers a bump for us historically

| Version | MSRV bump | Driver | Rationale committed at |
|---|---|---|---|
| 1.4.x | → 1.87 | `let ... else` stabilisation used across the parser layer | (recorded in prior CHANGELOG) |
| 1.4.10 | → 1.88 | Aligning with `windows-sys 0.60` + `smb2-client 0.2.x` toolchain baseline | 1.4.10 CHANGELOG |
| 1.5.0 | (unchanged, 1.88) | No new MSRV requirement introduced in the 1.5.0 workstreams | — |

## What is NOT covered

- The MSRV of the **sibling crates** (`smb2-client`, `dcerpc`, `hashglass`,
  etc.) is set in each sibling's own `Cargo.toml` and reviewed there. This
  policy governs only the adhammer workspace baseline.
- Nightly-only features are refused entirely — see `AI_RELEASE_GOVERNANCE.md`
  §4.1 "no undocumented feature". If a feature needs nightly, either wait
  for stabilisation or discard the feature.

## Non-goals

- Bumping MSRV to enable a feature that could be feature-flagged for older
  toolchains. Prefer the flag until the bump is otherwise justified.
- Tracking the "latest stable" release cadence for its own sake.
- Silently degrading below the declared MSRV. A crate that stops building
  on the declared MSRV is a bug, not a "we'll bump later" invitation.
