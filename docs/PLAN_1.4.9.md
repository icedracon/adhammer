# ADhammer 1.4.9 — hard plan (trust + polish, no new capability)

Written 2026-08-31 after the third-party audit of 1.4.8 (`docs/AUDIT_1.4.8.md`
if it lands in-tree; else the artifact link). Score today: **72/100**.
Target for 1.4.9: **80/100** (+8 recoverable in ~2 weeks). Path to 100 is
laid out in the audit's roadmap section for 1.5.0 and 2.0; 1.4.9 focuses on
the highest-ROI pieces that cost days, not weeks, and land immediately-
visible artifacts (SBOM, deny.toml, pre-commit hook, fuzz targets, SECURITY.md).

**Effort estimate:** 12–15 engineering days. No sibling-crate breaking
changes. No new attack vectors (all capability work stays in 1.5.0).

**Ship policy — 1.4.9 stays LOCAL.** Per operator directive, no crates.io
publishes this cycle. Every deliverable that touches a published sibling
crate (WS-DPAPI-BLOB-ORACLE code, WS-KEYWORDS-CASCADE) lands in the
git tree at 1.4.9 tag time but the actual publish is deferred to a
future release (1.4.10 or 1.5.0). SBOM + tag + prebuilt binaries on
GitHub Releases are fine; those are not crates.io publishes.

## Delta math — where the +8 points come from

| Sub-score | 1.4.8 | 1.4.9 | Δ | Workstream(s) |
|---|---|---|---|---|
| Testing            | 5 | 7  | +2 | WS-FUZZ-6 (+2) |
| Release discipline | 5 | 8  | +3 | WS-CI-HARDEN (+2), WS-LEAK-HOOK (+1) |
| Supply chain       | 6 | 8  | +2 | WS-CI-HARDEN (+1), WS-SBOM (+1) |
| Crypto             | 7 | 8  | +1 | WS-DPAPI-BLOB-ORACLE (+1) |
| Docs               | 8 | 9  | +1 | WS-DOC-TRUST (+1) |
| Architecture       | 8 | 8  |  0 | (WS-SDK-DECIDE only if we rename; move-CLI-into-lib is 1.5.0) |
| Protocol           | 8 | 8  |  0 | (1.5.0) |
| Ecosystem          | 8 | 9  | +1 | WS-KEYWORDS-CASCADE (+1) |
| **Total** | **72** | **80** | **+8** | ~12–15 days |

## Workstreams

### WS-LEAK-HOOK — pre-commit hook that grep-blocks lab identifiers

**Why.** Hard-rule enforcement in mechanics, not in memory alone. The
1.4.8 release day leaked a live lab credential twice — once through a KAT
constant, once through a commit message. Both would have been caught by a
grep pass on `git diff --cached` before the commit reached origin. Now
enforced by a pre-commit hook the author has to actively bypass with
`--no-verify` to leak.

**Deliverable.** `.githooks/pre-commit` executable script; `core.hooksPath`
pinned to `.githooks` in repo `.git/config` documentation; `docs/DEVELOP.md`
section explaining what the hook blocks and how to extend the term list.

**Blocks.** Any staged diff (added or modified lines) that matches
`Zikurat|4202935557|1141836847|93a18bf11f58cf|<extend as needed>`.
Extensible term list lives at the top of the script; contributors add
their own lab identifiers before their first commit.

**Cost.** 0.5 day.

### WS-CI-HARDEN — cargo package per-crate + GitHub Actions SHA-pinning + cargo-deny

**Why.** Two release-day CI regressions in 1.4.8 (LICENSE-MIT path + MSRV
bump from time 0.3.47) were only caught after the tag was cut, forcing a
force-move. A per-crate `cargo package --allow-dirty` job on every push
would have caught both two weeks earlier. Pinning Actions to commit SHAs
closes a supply-chain surface + silences the Node 20 deprecation warning.
cargo-deny gates license + source-registry + banned-crate policy.

**Deliverables.**
1. `.github/workflows/ci.yml` — new `package-check` job that runs
   `cargo package --allow-dirty -p <each of 12 crates>` on every push to
   `main` and every PR.
2. All `.github/workflows/*.yml` Actions references migrated from
   `@v4`/`@v2`/`@stable` to `@<40-char-sha>`, with a comment above each
   naming the tag the SHA came from.
3. `deny.toml` at the repo root — license allow-list, source-registry
   allow-list (`crates-io` only), banned-crate list (start empty, add on
   discovery), duplicate-version policy.
4. `.github/workflows/ci.yml` — new `cargo-deny` job.

**Cost.** 2–3 days (mostly Action-SHA lookup + `cargo deny check`
iteration until the workspace passes).

### WS-SBOM — SBOM per release + release attestation

**Why.** A regulated buyer's first ask after "is your CI green" is "where
is the SBOM?" cargo-cyclonedx produces CycloneDX-JSON that BOM viewers
(Dependency-Track, GitHub's Dependency Graph) accept. Ships as an
additional release asset alongside the prebuilt binaries.

**Deliverables.**
1. `.github/workflows/release.yml` — `sbom` job that runs
   `cargo cyclonedx --format json --output-cdx target/adhammer.cdx.json`
   after the build matrix, uploads `adhammer_<version>.cdx.json` +
   `.sha256` to the release page.
2. `docs/SUPPLY_CHAIN.md` — how to verify the SBOM + sigstore attestation
   + `.sha256` sidecars, one page.

**Cost.** 1 day.

### WS-FUZZ-6 — 6 fuzz targets for the parsers that touch attacker-controlled bytes

**Why.** The audit flagged 2 of ~40 parsers fuzzed. This closes the gap
for the six that touch attacker-controlled bytes end-to-end. Each target
is ~40 LOC of harness + a seed corpus (5–20 sample inputs) + a 24 h
scheduled run in CI on each release-candidate.

**Targets.**

| # | Target | Parser under test | Corpus source |
|---|---|---|---|
| 1 | `pac_parse` | `crates/kerberos/src/pac.rs::parse_pac` | Real PAC bytes from live DC (redacted) + adversarially-truncated variants |
| 2 | `pkinit_as_rep` | `crates/kerberos/src/pkinit.rs` AS-REP decode | Real AS-REP + truncated + wrong-oid |
| 3 | `ndr_unmarshal` | `dcerpc` sibling crate — moved upstream if it doesn't already fuzz | RPC response bodies |
| 4 | `smb2_response` | `smb2-client` sibling — same | SMB2 Session Setup / Tree Connect responses |
| 5 | `dpapi_blob` | `dpapi-offline::blob::DpapiBlob::parse` | Real blob bytes + boundary cases |
| 6 | `ldap_entry` | `adhammer-collector::to_object` | ldap3 `SearchEntry` shaped junk |

**Deliverables.** `fuzz/fuzz_targets/{pac_parse,pkinit_as_rep,ndr_unmarshal,smb2_response,dpapi_blob,ldap_entry}.rs`;
`fuzz/corpus/<target>/` with seed inputs; `.github/workflows/ci.yml`
release-triggered fuzz job (24 h each, nightly-only or manual, not on
every push).

**Cost.** 4–5 days.

### WS-DPAPI-BLOB-ORACLE — byte-oracle-validate the DPAPI blob decrypt chain

**Why.** The DPAPI masterkey chain was live-verified against impacket in
1.4.8-B. The DPAPI blob chain (below the masterkey layer) is still
unvalidated end-to-end. Same discipline: synthetic KAT via
`docs/synthetic_kat_blob.py` + ignored env-driven `test_real_dpapi_blob`
that operators can run against their own live blob.

**Deliverable.** `dpapi-offline` sibling crate patch: extend
`masterkey::tests` module with a `blob_roundtrip_kat` and a
`test_real_dpapi_blob_with_key` (ignored). New Python generator at
`docs/synthetic_kat_blob.py`. **Version bump + publish deferred** — the
code lands as 0.1.3-dev in the sibling repo; publish waits for the next
authorized crates.io cycle.

**Cost.** 1.5 days.

### WS-DOC-TRUST — SECURITY.md + THREAT_MODEL.md + API stability

**Why.** The audit-flagged docs gap is not about volume (README + CHANGELOG +
VECTORS + PLAN are all serious) but about *trust posture* docs a security
reviewer expects — how to report a vuln, what the tool's threat model is,
what stability guarantees each sibling crate carries.

**Deliverables.**
1. `SECURITY.md` — disclosure policy + PGP key + response SLA. GitHub
   surfaces this on the repo Security tab.
2. `docs/THREAT_MODEL.md` — assets (operator credentials, target-DC
   secrets, wire captures), actors (operator, target DC admin, LDAP peer,
   local attacker on operator box), trust boundaries (network read,
   network write, filesystem write, terminal display), non-goals (not a
   defensive tool, not a persistence framework, not an Azure/Entra
   product).
3. `docs/STABILITY.md` — per-sibling-crate API-stability tier (bottom of
   stack `windows-sddl`/`ad-acl` → 1.0 candidates; middle `dcerpc` → 0.x
   with breaking-change note per release; top `ms-icpr` → 0.x, active).

**Cost.** 2 days.

### WS-SDK-DECIDE — rename or delete the 49-LOC `adhammer-sdk` stub

**Why.** The audit called the current `adhammer-sdk` (49 LOC re-export
shim) dishonest — the name promises a library surface that doesn't
exist. Two options:

- **A.** Rename `adhammer-sdk` → `adhammer-lib`, keep it as a re-export
  shim, document explicitly that "the library surface is the individual
  sibling crates". Low effort, low value. Just changes the name-lie.
- **B.** Actually move ~5 k LOC of orchestration from `cli/` into
  `adhammer-sdk` (or `adhammer-lib`), so downstream tools can compose
  without invoking the binary. Deferred to 1.5.0 (see WS-CLI-SHRINK).

**Decision for 1.4.9.** Pick **A** only if we can do it in one day
without breaking the SDK crate's crates.io name. Otherwise leave as-is
and let WS-CLI-SHRINK in 1.5.0 solve it properly.

**Cost.** 0–1 day.

### WS-KEYWORDS-CASCADE — republish 12 crates so keywords go live on crates.io

**Why.** 1.4.8-hardening added keywords + categories to every sibling
Cargo.toml in the git tree, but crates.io reads keywords from the
uploaded package — they take effect on the *next* publish. Republishing
1.4.9 across all 12 crates propagates the discoverability metadata.

**Deliverable.** Standard bottom-up cascade publish (documented in
1.4.8's audit as one command per crate; ship-script would help). Each
crate at 1.4.9.

**Cost.** 1 day (mostly waiting for crates.io to index between publishes).

**Ship-policy note.** Deferred to 1.4.10 or 1.5.0 — 1.4.9 stays local per
operator directive. Keywords already live in the git tree; ready-to-ship
whenever the next publish cycle opens.

## Non-goals for 1.4.9

- No new attack verbs. Every capability workstream lives in 1.5.0.
- No breaking API changes in sibling crates. All 1.4.9 sibling bumps are
  patch-level.
- No cross-Windows-version test matrix expansion. VBox images for 2019 +
  2022 land in 1.5.0.
- No `cli/` shrink. The CLI-into-lib refactor is a 1.5.0 workstream.
- No external security audit. That's a 2.0 workstream.
- No Azure/Entra. Permanent no.

## Ship gate

`cargo audit` — 0 vulnerabilities.
`cargo deny check` — pass on license + sources + duplicates.
`cargo package -p X --allow-dirty` — green on every crate.
`cargo test --workspace --no-fail-fast` — 242+ pass.
`cargo clippy --workspace --all-targets -- -D warnings` — exit 0.
SBOM asset uploaded per release.
Every GitHub Action pinned to a commit SHA.
Pre-commit hook installed in `.githooks/`.
SECURITY.md + THREAT_MODEL.md + STABILITY.md all present.
6 fuzz targets scaffolded with corpus seeds.
DPAPI blob chain KAT green.
Every sibling crate republished at 1.4.9 with keywords live on crates.io.

## Release cadence

- 1.4.9-rc.1 tag on `main` when 6/8 workstreams shipped.
- Ship 1.4.9 tag when all 8 ship gates green.
- Force-move discouraged; if a same-day bug lands, cut 1.4.9.1.
- 1.5.0 workstream planning begins as soon as 1.4.9 is tagged.
