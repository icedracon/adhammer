# ESC Explorer — presentation update

## Scope

Replace the terse coverage orbit with an accessible ESC1–ESC16 explorer:
select a class, read its meaning, replay an illustrative inspection sequence,
inspect a verified defensive command where applicable, and review limitations
and remediation. Keep the existing Observatory, dragon, release, and install flow.

## Delivery order

1. Replace broad support badges with check-specific evidence boundaries.
2. Add responsive selection and a short, pausable inspection animation.
3. Add explanations, prerequisites, command behavior, and interpretation.
4. Check data completeness, syntax, links, motion handling, and existing tests.
5. Publish the site through the existing GitHub Pages setup.

## Truth and safety boundaries

- Examples describe v1.5.1; no version, Rust implementation, package, release,
  dependency, or validation-ledger changes are part of this update.
- Commands are documentation only. The browser never executes them and does
  not collect credentials. No live assessment is part of development.
- Configuration reads and HTTP exposure probes are network operations, not
  offline tests. No issuance, relay, permission modification, or exploitation
  recipes are included. No recommendation to enable Remote Registry or bypass TLS.
- Template analysis is not a full ACL/CA audit. Registry reads depend on target
  role and access. Missing data and empty output do not prove safety.
- ESC12 remains outside this site's documented ADhammer scope. Classes without
  a verified focused defensive command receive a manual-review explanation.
- The taxonomy shown is the site's existing ESC1–ESC16 scope, not a claim to
  enumerate every known AD CS issue. Support remains governed by VALIDATION.md.

## Sources

- `cli/src/checks/adcs.rs`, `cli/src/enums/adcs.rs`,
  `cli/src/enums/esc_registry.rs`, `crates/checks/src/rules/esc.rs`.
- `docs/VALIDATION.md`, installed v1.5.1 CLI help (local-only inspection).
- [Microsoft certificate posture guidance](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates).
- [Microsoft certificate mapping guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

The existing README Observatory GIF is unchanged. A separate ESC GIF is a
follow-up after the interactive explorer, not a new recording of CLI output.

## Local checkpoint — 2026-09-15

Implemented the explorer and its documentation-only examples. Local checks
passed: `test_site_esc.cjs`, `test_site_observatory.cjs`,
`test_site_entrance.cjs`, validation-ledger check (87 rows), and diff whitespace.
The new behavior test uses a hermetic DOM fixture; it is not browser visual QA.

Publication is paused under the repository governance policy. Existing main
`146415c4ce8d4e96c6d375e804fbe27a19349836` has a failed
[cargo-deny job](https://github.com/icedracon/adhammer/actions/runs/34961764732/job/104356758250).
The failed step is `cargo deny check`. Its job log reports
`RUSTSEC-2026-0285` against locked `rustls 0.23.43`, with a recommended
upgrade to `>=0.23.45`. Bans, licenses, and sources passed; advisories failed.
This update has no dependency or Rust-code changes.
No new commit or push was made for this explorer. Maintainer direction is
required before resolving the separate CI problem or authorizing a scoped
site-only publishing exception.

## Circular selector refinement

User requested the ESC classes in a circle with scroll-driven selection.
The local preview now uses a rotating, upright-label dial. Wheel gestures over
the dial step through ESC1–ESC16; gestures at the sequence boundaries return
to native page scrolling. Trackpad bursts are throttled. Zoom gestures are
not intercepted. Horizontal touch swipes, previous/next controls, clicking,
and keyboard selection remain available; vertical touch scrolling is native.
Reduced-motion and pause preferences disable rotation transitions without
disabling selection. Hermetic interaction tests cover these behaviors.
No command content, dependency, publishing authorization, or blocker changed.

## Scoped publishing authorization — 2026-09-15

After the CI blocker and local-only status were disclosed, the maintainer
explicitly requested: "cool push". This authorizes committing and publishing
this site-only update to the existing main / GitHub Pages surfaces despite
the known dependency-check failure. It supersedes the publication pause above
for this presentation patch only; it does not waive the advisory for a release.

The rustls advisory remains unresolved. No dependency, lockfile, Rust code,
version, tag, package, GitHub Release, or registry change is authorized or
included. README/profile assets and install/platform claims remain unchanged.
Website tests and the validation-ledger check must pass before pushing; the
Pages deployment must succeed before the website is described as published.
