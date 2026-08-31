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

## Signing key custody

Release artifacts on the GitHub Releases page are signed via sigstore
OIDC. The workflow is defined in `.github/workflows/release.yml`; the
signing identity is the GitHub Actions runner's OIDC token, verifiable
via `cosign verify-blob`. There is no long-lived signing key to
rotate; every release is signed by a fresh short-lived token.

crates.io publishes are signed with the maintainer's crates.io API
token. Rotation policy: token rotated on suspected compromise, on
maintainer handoff, and at minimum once per year.
