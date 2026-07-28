# Security Policy

## Intended use

ADhammer is an offensive-security **and** audit toolkit for Active Directory. It implements
working attack primitives — Kerberos roasting, DCSync, golden/silver ticket forging,
pass-the-ticket, NTLM relay, ADCS abuse, and remote code execution — alongside a passive
PingCastle-style auditor.

It is published for **authorized security testing, research, and education only**:

- penetration testing and red-team engagements **with written authorization**,
- security research in an **isolated lab you own** (the `lab/` scripts build one),
- academic use and CTFs,
- defensive validation (confirming a hardened DC rejects a given technique).

Using these capabilities against systems you do not own or are not explicitly authorized to
test is illegal in most jurisdictions. The authors accept no liability for misuse. If you are
not certain you are authorized, you are not authorized.

This is the same dual-use posture as impacket, Rubeus, mimikatz, and PingCastle: the
techniques are already public and used by real adversaries; a clear, auditable open
implementation helps defenders reproduce, detect, and mitigate them.

## Reporting a vulnerability

To report a security issue **in ADhammer itself** (e.g. a parser that can be crashed or
exploited by a malicious server response), please open a
[GitHub Security Advisory](https://github.com/icedracon/adhammer/security/advisories/new)
or email the maintainer rather than filing a public issue. We aim to acknowledge within
72 hours.

Please do **not** use the issue tracker to report vulnerabilities in third-party products
you discovered while using ADhammer — report those to the affected vendor under their own
disclosure process.

## Supported versions

ADhammer is pre-1.0; only the latest `main` receives fixes.
