# v1.5.2 presentation update — 2026-09-20

Scope: website and README only. Maintainer requested the v1.5.2 rebuild,
continuous animations, ten starting workflows alongside the existing method
catalog, then explicitly instructed “push”. No Rust code, dependency, package
version, release, tag, credential, or CI policy is changed by this update.

Baseline: main f847b4f94315025f6518438376ff25ecbf2daf63, with successful CI
https://github.com/icedracon/adhammer/actions/runs/35495532992 . Newer upstream
receipt-test and ledger fixes were fast-forwarded without changing them.

Public release facts: GitHub v1.5.2 is published with platform binaries and
checksum sidecars; the crates.io API reports CLI v1.5.2 created September 20,
2026 and not yanked. Package installation, binary checksums, attestations, all
sibling crate versions and docs.rs were not independently re-certified in this
presentation task; this document is not an ecosystem release receipt.

Content: six source-checked defensive CLI methods; ten README starting
workflows (curated, not a popularity ranking); three silent illustrative MP4
loops. No live target commands were executed. No synthetic output is presented
as real assessment evidence. Existing README catalog is retained.

Checks: test_site_cli.cjs, test_ambient_video.cjs, test_site_esc.cjs,
test_site_observatory.cjs, test_site_entrance.cjs, validation-ledger checker,
JavaScript syntax and git diff whitespace checks pass. Browser inspection
verified all three videos autoplay when visible, offscreen videos pause, and
local/global pause controls work. Reduced motion and background-tab suspension
also pass the deterministic motion-controller test. MP4s decode successfully;
total encoded video size is approximately 348 KB.

Deployment: existing GitHub Pages provider, gh-pages branch root. Preserve
that configuration. Copy only reviewed site assets, never the repository or
local private files. Revert the presentation commits to roll back; do not
retag the v1.5.2 software release. Older unfinished README drafts remain in
their original checkout and are not included.
