# ADhammer 1.6.0 — Release post draft (for GitHub Releases + launch channels)

> This file is the human-readable release story — distinct from CHANGELOG.md,
> which is technical and complete. Paste this to the GitHub Release page on
> publish day. Delete this file in 1.6.1 (one-shot asset).

---

**Title**: ADhammer 1.6.0 — reports your SOC can audit

**Tag**: v1.6.0

**Pre-release**: No (minor release)

**Release body (paste to GitHub)**:

---

Reports now carry a hash-footer provenance line and **engagement-over-engagement baseline-diff** keyed on `(id, affected_object)` — when a finding gets disputed, the audit trail ends the dispute, and next quarter's assessment picks up where this quarter's left off. The HTML deliverable ships with a light/dark theme toggle and a print stylesheet so the PDF is a client artifact, not a dev dump.

Under the hood, PAC_CREDENTIAL_INFO AES128/256 decrypt now routes through the standalone [`kerbcore`](https://crates.io/crates/kerbcore) crate instead of `picky-krb` — Phase-1 of a pure-Rust Kerberos stack with no managed-runtime detection surface. No .NET, no AMSI, no CLR load — just syscalls and a receipt. The companion [`ms-pac-forge 0.2.0`](https://crates.io/crates/ms-pac-forge) sibling release exposes the forge primitives (Golden / Silver / Diamond / Sapphire) as a focused standalone crate for anyone building their own pure-Rust Kerberos tooling.

**What this release ships**
- `kerbcore` AES128/256 decrypt in `attack unpac` and the DCSync credential path
- `attack asktgt` ccache UX: refuses to overwrite prior attack evidence with a one-click remedy (preserves the writer's defensive semantics)
- Unified `diag::fix_hint` across main / interactive / guided — every operator-visible error names the actual remedy (TCP-reset ≠ unreachable, AD CS policy denial ≠ TLS, 8 KDC numeric error codes translated)
- Scheme/port-swap guard rejects `ldap://` on 636 and `ldaps://` on 389 before any bind
- ESC registry probe retry on `STATUS_PIPE_NOT_AVAILABLE` with 4× backoff
- Report redesign — `crates/report/src/design.rs` + split template; `data-theme-toggle` for light/dark; `@media print` for clean PDFs; schema-versioned JSON

**Experimental in 1.6.0** (requires `ADHAMMER_EXPERIMENTAL=1` to run)
- `attack rbcd` and `attack constrained` — the full S4U2Self + S4U2Proxy chain runs and returns the final impersonation ticket's enctype as proof the chain completed, but the ticket is NOT yet persisted to a ccache usable by downstream tooling. Full transport wires up in a later 1.6.x release.

**Security**
- rustls 0.23.45 → 0.23.46 closes 4 CVEs (RUSTSEC-2026-0346 / 0347 / 0348 / 0349). None triggered ADhammer's default-build threat model, but closing before publish was the honest move.

**Upgrade**
```sh
cargo install --locked adhammer --force
```

**What's next in 1.6.1**
Next: LDAP CBT (the biggest gap against hardened DCs), full S4U transport, hickory-dns, Shadow Creds + MAQ.

Full technical detail: [CHANGELOG.md](CHANGELOG.md).

**Thanks**
To the operators who hit the ccache UX bug in a 2am session and surfaced the fix-hint gaps. Those sessions shaped this release.
