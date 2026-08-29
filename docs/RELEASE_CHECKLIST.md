# Release checklist

Per-release ops steps. Run in order. Skip nothing without a written reason.

## 1. Pre-tag gate

- `cargo fmt --all` — clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0
- `cargo test --workspace --no-fail-fast` — every test green
- Live-verify against a real DC (Kali or Windows against the lab):
  - `scan --url ldaps://<dc>:636 --user <bind> --password <...> --insecure --out-all /tmp/verify`
  - Expect: expected finding count matches `docs/VALIDATION.md`, all four
    `--out-all` files present, byte-identical `report.json` sha256 across
    back-to-back same-env runs.

## 2. Version bump + CHANGELOG

- Bump `Cargo.toml::version` at the workspace root and each internal
  dep-pin under `[workspace.dependencies]` (grep them, do not miss any).
- Bump the "Release Truth" version + date in `README.md`.
- Prepend a `## [x.y.z] — YYYY-MM-DD` section to `CHANGELOG.md` under
  `[Unreleased]`. Document security fixes first, then quality, then new
  workstreams. Include an explicit **Gate** section stating what the
  test / clippy / fmt / live-verify status was at ship.

## 3. Tag + push

- `git tag -a vX.Y.Z -m "adhammer X.Y.Z — <one-line theme>"`
- `git push origin main`
- `git push origin vX.Y.Z`

## 4. Bottom-up crates.io publish

Order (must not change — each crate's `[dependencies]` names the next):

1. `adhammer-core`
2. `adhammer-secrets`
3. `adhammer-ldap`
4. `adhammer-graph`
5. `adhammer-collector`
6. `adhammer-sysvol`
7. `adhammer-kerberos`
8. `adhammer-bloodhound`
9. `adhammer-checks`
10. `adhammer-report`
11. `adhammer-sdk`
12. `adhammer` (CLI)

For each: `cargo publish --dry-run -p <crate>` then `cargo publish -p <crate>`.
Wait for each to appear on crates.io before moving to the next (cargo
handles the wait automatically, no `Ctrl+C`).

## 5. GitHub Release page

- Open `https://github.com/icedracon/adhammer/releases/tag/vX.Y.Z`.
- **Title:** `adhammer X.Y.Z — <one-line theme>`.
- **Body:** copy the `## [X.Y.Z]` section from `CHANGELOG.md`.
- Attach prebuilt binaries (when WS-BINSTALL CI is live: automatic).
- Publish.

## 6. WS-DEFENDER-SUBMIT — Microsoft false-positive queue

**Why:** every fresh Windows `cargo install adhammer` currently trips
Windows Defender with `os error 225 — file contains a virus or
potentially unwanted software`. The `docs/install.ps1` one-liner
works around this per-user; Microsoft reputation build-up is the only
scaling fix short of buying a code-signing certificate.

**Steps** (once per release, ~5 minutes):

1. Compute the release binary SHA-256:
   ```powershell
   Get-FileHash -Algorithm SHA256 $env:USERPROFILE\.cargo\bin\adhammer.exe
   ```
2. Visit https://www.microsoft.com/en-us/wdsi/filesubmission — sign in with
   any Microsoft account (personal is fine; no MS partnership required).
3. Select **"Software developer"** as submitter type.
4. Fields:
   - **Company name:** icedracon
   - **File:** upload the release exe from `~/.cargo/bin/adhammer.exe`
     (or the GitHub Release attachment once WS-BINSTALL ships)
   - **Detection name:** whatever Defender showed (usually `Trojan:Win32/*`)
   - **Definition version:** run `Get-MpComputerStatus | Select-Object
     AntivirusSignatureVersion` on the reporting machine
   - **Category:** *Incorrect detection*
   - **Additional info:** copy the paragraph below.

**Additional-info paragraph** (paste verbatim, adjust version):

> adhammer is an open-source Active Directory security assessment CLI
> written in Rust, published to crates.io and github.com/icedracon/adhammer.
> The binary is compiled from source on the user's machine via
> `cargo install adhammer` and quarantined immediately after the build.
> Source is fully auditable at the tagged commit; this submission is for
> tag vX.Y.Z (SHA-256: <hash>). The project ships no packers, obfuscators,
> installers, or network beacons of any kind — it is a defensive AD
> auditing tool that connects only to endpoints the operator names via
> command-line flags. No behavior differs between the source and the
> compiled binary; the detection is heuristic.

5. Submit. Record the ticket URL in the release notes for this version.
6. Response time: usually 3-14 days. If accepted, subsequent installs of
   the same hash pass Defender cleanly for a window (typically 30 days
   on that machine before signature refresh reverts). Long-term fix is
   still a real code-signing certificate.

**Automation stub for a future release** — a GitHub Actions workflow could
compute the release hash, open the submission page pre-filled via URL query
params, and file the ticket via headless Chromium. Not built for 1.4.8;
manual is fine at current release cadence.

## 7. Post-ship

- Push a short release notice (English + RU) to the announcement channels
  you use. See `docs/PLAN_1.4.8.md` "celebration text" pattern from 1.4.7
  for tone (technical, terse, no oversell, no competitor mentions).
- Update `docs/VALIDATION.md` with the release version + date + the
  live-verify results from step 1.
- Open the next `docs/PLAN_X.Y.Z.md` file for the following release with
  known-open items from the shipped one. Loud "non-goals" section per
  1.4.8 pattern.
