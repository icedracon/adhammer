# Security policy

ADhammer is an offensive Active Directory security assessment tool. Use it
against systems you own or have written authorization to test. The rest of
this document is for people who find a bug **in ADhammer itself** — the
tool's own attack surface, not the AD attacks it implements.

## Reporting a vulnerability

Report privately to **security@icedracon.dev** with the subject prefix
`[adhammer-vuln]`. If you prefer, use GitHub's private-vulnerability-
reporting flow at
<https://github.com/icedracon/adhammer/security/advisories/new>.

**Please include:**

- The affected crate (`adhammer`, `adhammer-kerberos`, `dpapi-offline`,
  etc.) + version.
- Reproduction — a minimal command, a fuzz corpus input, or a wire
  capture.
- Impact — what the bug does that it shouldn't, and to whom.

**Do NOT** include real customer / target credentials, real SIDs, or
real live-lab identifiers in the report. Use placeholders
(`<password>`, `S-1-5-21-XXXX-YYYY-ZZZZ-500`, `<dc-ip>`); the pre-commit
hook in `.githooks/pre-commit` documents the discipline.

## Response SLA

| Severity | First response | Fix / disclosure |
|---|---|---|
| Critical (RCE on operator, credential leak in a release) | 48 h | 7 days |
| High (crash on hostile server, incorrect signing/sealing, missing bounds check on attacker-controlled bytes) | 5 days | 21 days |
| Medium (documentation gaps, false positive that could mislead an audit) | 14 days | 60 days |
| Low (typos, cosmetic issues) | best-effort | best-effort |

Timelines are measured from a triage-able first message. Weekends /
holidays may add up to 48 h.

## Scope

**In scope:**

- The `adhammer` binary and its interactive session, HTML report,
  attack orchestration.
- Every crate published from this repository — `adhammer-*`.
- Every icedracon sibling crate published from the same organization —
  `dcerpc`, `ntlmssp`, `smb2-client`, `ms-*`, `dpapi-offline`,
  `dpapi-ng`, `windows-sddl`, `ad-acl`, `ese-parser`, `ccache-io`,
  etc. (See `docs/STABILITY.md` for the full list.)
- Release artifacts on the GitHub Releases page (prebuilt binaries,
  `.deb`, `.sha256` sidecars, sigstore attestations).

**Out of scope:**

- Bugs in the Active Directory attacks the tool *implements* — those are
  Microsoft's protocol behaviour, not ours. Report to MSRC if you find a
  novel AD flaw.
- Vulnerabilities in `picky-krb`, `ldap3`, `rustls`, or other upstream
  Rust crates. Report to those crates' maintainers.
- Configuration mistakes on the target DC (weak passwords, missing
  patches). Those are what the tool *detects*, not what it is.
- Anything requiring an attacker to already have arbitrary code
  execution on the operator's machine.

## Coordinated disclosure

We aim to publish a fix and an advisory (RustSec, GitHub Security
Advisory) at the same time. Reporters are credited unless they ask
otherwise.

## Cryptographic key material

The `adhammer_core::Redacted<T>` wrapper hides secret material from
`Debug` / `Display` and requires a greppable `.expose()` at every read
site. If you find a code path that logs, formats, or stores a secret
without the wrapper, that is a valid vulnerability report at the "High"
tier at minimum.

## Known long-standing issues

- **`rsa` 0.9.x Marvin timing sidechannel** (RUSTSEC-2023-0071). No
  upstream fix exists for any pure-Rust RSA crate. Documented in
  `.cargo/audit.toml` with rationale. Revisit annually.
- **`rustls-pemfile` 2.x unmaintained** (RUSTSEC-2025-0134). Upstream
  migrated to `rustls-pki-types`; our transitive graph is not yet on
  the new stack. Documented in `deny.toml` with rationale.

## Signing key custody + rotation policy

Two signing surfaces exist. Both are formally scoped below.

### 1. Release artifacts on GitHub Releases — sigstore OIDC

Every prebuilt binary (`.exe`, `linux-gnu`, `linux-musl`, `apple-darwin`)
plus the `.deb` on the GitHub Releases page is signed via a
sigstore OIDC attestation issued to the GitHub Actions runner's
short-lived token. The workflow is
`.github/workflows/release.yml`; verifiable end-to-end via:

    gh attestation verify <asset> --owner icedracon

**Custody model:** there is no long-lived signing key. Every release
receives a fresh short-lived token; nothing needs to be rotated because
nothing is retained.

**Rotation policy:** N/A (no long-lived key).

**Compromise response:** if a runner-token compromise is ever detected
(e.g., a leaked GitHub Actions token), we (a) revoke it via the GitHub
UI, (b) republish the release with a fresh attestation, (c) file a
GitHub Security Advisory naming the compromised artifact SHAs, (d)
yank all crates from that release.

### 2. crates.io publishes — maintainer API token

Every crate on <https://crates.io/users/icedracon> is published under
the maintainer's crates.io API token. This is a long-lived credential
and requires an explicit rotation cadence.

**Custody model:** token lives in the maintainer's password manager;
never in the git tree, never in a CI secret, never in a screenshot.

**Rotation policy — mandatory:**

- **Annual:** rotated at least once per calendar year, on or before
  the anniversary of the previous rotation.
- **On suspected compromise:** immediately, before any other action.
- **On maintainer handoff / access changes:** immediately.

**Rotation procedure:**

1. Generate a new token on <https://crates.io/settings/tokens>, scoped
   to `publish-update` only (never `publish-new` — no reason to
   publish new crates under this identity today).
2. Update the maintainer's password manager entry with the new token.
3. Revoke the previous token immediately from the same page.
4. Post the rotation event (not the token) into
   `docs/SIGNING_ROTATIONS.md` as an append-only log entry, dated.
5. If the rotation was compromise-triggered, publish a GitHub
   Security Advisory naming the suspected compromise window and any
   affected publishes.

### 3. crates.io org membership

Every icedracon crate on crates.io has exactly one owner (the
maintainer identity). No secondary owners today. Adding a co-owner
requires an explicit ADR + a same-day advisory listing the new
identity.

### 4. Third-party trust surface

Runtime signing for downstream consumers relies on:

- sigstore attestations verified via `cosign` / `gh attestation`.
- crates.io's own package-index HTTPS-only distribution.

We do NOT publish binaries via HKP / OpenPGP-signed tarballs / any
other signing surface. Downstream that needs an air-gapped verification
path uses `cargo binstall --no-download` + manual sha256 sidecars from
the GitHub Releases page.
