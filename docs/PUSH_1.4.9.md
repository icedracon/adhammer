# ADhammer 1.4.9 — careful push plan

Written 2026-09-01. This is the hand-off block the operator runs when
they authorize the 1.4.9 push. Every step below is idempotent up to
the actual `cargo publish` call, which is irreversible per
`feedback-ship-workflow`.

**Nothing here runs automatically.** Read the whole file first, decide
`go` per step, then execute one wave at a time.

## Pre-push hygiene (mandatory)

### 1. Squash the two plan commits into one clean commit

Commit `e92eaeb` (the 1.5.0 plan revision) accidentally included two
lab IPs verbatim. Commit `afd6966` redacted them. Before push, squash
the two so the public git log carries only the redacted form.

```bash
cd C:/Users/zevs/Documents/adhammer
git rebase -i HEAD~2
# In the editor, change the SECOND line ("afd6966 docs: redact IPs")
# from `pick` to `fixup`; keep the FIRST line (`e92eaeb`) as `pick`.
# Save + exit. The result: one commit with the redacted text only.
```

Verify:

```bash
git log -1 --stat
# Expect: "docs: hard PLAN_1.5.0.md — post-SEC-1-close scope + picky-krb path"
#         1 file changed, ~110 insertions, ~40 deletions
git show HEAD -- docs/PLAN_1.5.0.md | grep -E '192\.168\.0\.52|172\.29\.|172\.20\.'
# Expect: NO OUTPUT (leaked IPs gone from the surviving commit's diff)
```

### 2. Strip `[patch.crates-io]` from Cargo.toml

The `windows-sddl = { path = "../windows-sddl" }` patch is dev-only.
GitHub CI + `cargo publish` both refuse relative-path deps.

```bash
# Edit Cargo.toml — DELETE the entire block:
#   [patch.crates-io]
#   windows-sddl = { path = "../windows-sddl" }
# The `windows-sddl = "0.1.3"` line in [workspace.dependencies] stays;
# after the sibling publish (step 3 below) it resolves against crates.io.
```

Verify:

```bash
grep -n 'patch.crates-io\|../windows-sddl' Cargo.toml
# Expect: NO OUTPUT
```

### 3. Fresh ship-gate rerun

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All three must be GREEN before any publish command. Session-2026-09-01
snapshot: fmt clean, clippy 0 warnings, 269 tests pass / 0 fail /
20 ignored (18 requires-network + 2 slow-path).

### 4. Final leak sweep across the whole diff about to be pushed

```bash
git diff origin/main..HEAD --unified=0 |
    grep -iE '^\+.*(Zikurat|TestPass2026|4202935557|1141836847|93a18bf11f58cf|192\.168\.91\.20|192\.168\.0\.52|172\.29\.|172\.20\.118|172\.24\.174)'
# Expect: NO OUTPUT

git log origin/main..HEAD --format=%B |
    grep -iE '(Zikurat|TestPass2026|4202935557|1141836847|93a18bf11f58cf|192\.168\.91\.20|192\.168\.0\.52|172\.29\.|172\.20\.118|172\.24\.174)'
# Expect: NO OUTPUT
```

If either sweep hits, STOP. Redact and rebase-squash before continuing.

## windows-sddl 0.1.3 publish first (crates.io + tag)

The adhammer publish depends on this being on crates.io.

```bash
cd C:/Users/zevs/Documents/windows-sddl
grep -n 'AclSize\|DaclKind\|SE_DACL_PRESENT' src/lib.rs | wc -l
# Expect: ~10+ hits (WS-001+002 code present)

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

cargo publish --dry-run
# Read the manifest summary carefully.
# Look for: name = "windows-sddl", version = "0.1.3", no path deps left.

cargo publish
# Irreversible. Cannot re-use 0.1.3 if this succeeds.

git tag v0.1.3
git push origin main --tags
```

Wait ~30 s for the crates.io index to update before starting the
adhammer publish.

## adhammer 1.4.9 publish — bottom-up 12 crates

Every crate uses `version.workspace = true`, so the workspace's
`1.4.9` pin drives everything. Publish in the 6 waves below. Do
`--dry-run` for each crate BEFORE the real publish.

Between waves: wait ~30 s for the crates.io index to catch up so the
next wave's `cargo publish` can resolve its just-published deps.

**Wave 0 (no adhammer-* deps):**

```bash
cd C:/Users/zevs/Documents/adhammer
cargo publish -p adhammer-core --dry-run    && cargo publish -p adhammer-core
cargo publish -p adhammer-ldap --dry-run    && cargo publish -p adhammer-ldap
cargo publish -p adhammer-secrets --dry-run && cargo publish -p adhammer-secrets
sleep 30
```

**Wave 1 (depend on adhammer-core):**

```bash
for c in adhammer-bloodhound adhammer-collector adhammer-graph \
         adhammer-kerberos adhammer-sysvol; do
    cargo publish -p "$c" --dry-run && cargo publish -p "$c" || break
done
sleep 30
```

**Wave 2 (depends on core + graph):**

```bash
cargo publish -p adhammer-checks --dry-run && cargo publish -p adhammer-checks
sleep 30
```

**Wave 3 (depends on core + graph + checks):**

```bash
cargo publish -p adhammer-report --dry-run && cargo publish -p adhammer-report
sleep 30
```

**Wave 4 (depends on 6 sub-crates):**

```bash
cargo publish -p adhammer-sdk --dry-run && cargo publish -p adhammer-sdk
sleep 30
```

**Wave 5 (CLI, top of stack):**

```bash
cargo publish -p adhammer --dry-run && cargo publish -p adhammer
```

If any dry-run flags a missing README, license, or metadata issue,
stop and fix it in an in-place commit before continuing. Do NOT
publish half-a-wave and leave the rest half-published.

## Tag + push

```bash
cd C:/Users/zevs/Documents/adhammer
git tag v1.4.9
git push origin main --tags
```

Pushing the tag triggers `release.yml`, which runs the release-build
matrix (Linux x86_64, Windows x86_64, macOS aarch64), the SBOM job,
the `.deb` packaging (per WS-DEB-PACKAGE from 1.4.9), and the
sigstore attestation via GitHub OIDC (per WS-INSTALL-PS1 +
WS-BINSTALL). The `.sha256` sidecar + SBOM + attestation land on the
GitHub Release page automatically.

## GitHub release polish (manual, after CI publishes the assets)

1. Open https://github.com/icedracon/adhammer/releases/tag/v1.4.9 .
2. Set the release title to `adhammer 1.4.9 — SEC-1 remediation`.
3. Paste the CHANGELOG `[1.4.9]` section verbatim into the release body,
   plus a footer:

   ```markdown
   ---
   ## Verify

   - Prebuilt binaries + `.deb` + `.sha256` sidecars are attached below.
   - The `adhammer_1.4.9.cdx.json` CycloneDX SBOM lists every direct + transitive dep.
   - The sigstore attestation proves the binaries came from this exact
     commit (`git rev-parse HEAD^{tree}`) via GitHub OIDC.
   - Reproducibility: `SOURCE_DATE_EPOCH` was pinned during the release
     build; anyone can re-run `release.yml` from this tag and get
     bit-identical binaries (WS-REPRO).
   ```

4. **Do NOT** attach a Windows installer or PowerShell one-liner that
   fetches from a domain adhammer does not own; the existing
   README's `iwr | iex` block already covers this.
5. Publish the release (still on the same page).

## Post-push memory + doc updates

```bash
# In the private memory store:
# - project_adhammer.md: bump the header to "adhammer live=1.4.9",
#   note the SEC-1 close, the picky-krb-defer, and the 2/3 Windows-
#   receipt state.
# - project_testlab_creds.md: refresh with the 2019 VM IP once you've
#   booted it + captured the current address.
# - MEMORY.md: no index change (project_adhammer entry stays).
```

## Rollback if a mid-wave publish fails

- If `cargo publish -p X --dry-run` fails, STOP the wave. Do NOT
  publish the remaining wave items until X's manifest is fixed +
  a follow-up commit lands.
- If `cargo publish -p X` SUCCEEDS but a later crate in the same
  release fails, the successful publishes are permanent. `cargo
  yank -p X --version 1.4.9` marks the slot "do not download" but
  cannot re-use the version. In that case bump the WHOLE workspace
  to 1.4.10 (single sed) + start the wave sequence over.
- Yanks are irreversible for slot re-use per
  `feedback-adhammer-hard-rules` §"Yanks are irreversible".

## Session-2026-09-01 checkpoint

Commits ready to push (in order):

1. `9752c8f` — 1.4.9 fuzz: upload crash artifacts (pre-session)
2. `1fd4b80` — 1.4.9 SEC-1 remediation batch: close AH-001..007 + WS-001/002
3. `f4e163b` — docs+receipts: 1.4.9 SEC-1 changelog + 2025/2022 live-validation
4. `e92eaeb` — docs: hard PLAN_1.5.0.md — post-SEC-1-close scope + picky-krb path
5. `afd6966` — docs: redact IPs from 1.5.0 plan (follow-up to e92eaeb)

Step 1 above squashes 4+5 into one clean commit. Final local head after
squash: `9752c8f → 1fd4b80 → f4e163b → <squashed plan commit>` = 4
commits ahead of `origin/main`, plus 1 commit ahead of `windows-sddl`
`origin/main` (`bb57722`).
