<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-core</h1>

<p align="center"><em>Core types — SID, GUID, Snapshot, Finding, MITRE mapping, redaction, scope, sanitization.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-core"><img src="https://img.shields.io/crates/v/adhammer-core?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-core"><img src="https://img.shields.io/docsrs/adhammer-core?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

The lowest-layer crate of the ADhammer workspace. Every other `adhammer-*`
subsystem imports this. Contains only pure types + a handful of small
utility helpers — no I/O, no protocol parsers, no network stack.

- **AD identifiers** — `Sid` (Security Identifier), `Guid`, `AdObject`
  (the normalized snapshot row).
- **Finding surface** — `Finding`, `Category`, `Severity`, `Evidence`,
  MITRE ATT&CK tags, wire-frame `WireExchange` for reproducible per-verb
  evidence.
- **Secret boundary** — `Redacted<T>`, `SecretString`, `SecretBytes` with
  `zeroize`-on-drop; `Debug`/`Display` print `"***"` so a stray
  `tracing::debug!` cannot leak.
- **Scope + runner control-plane (1.4.10)** — `EngagementScope`,
  `ScopeTarget`, `CheckId`, `CheckClass`, `Capability`,
  `CapabilityKind`, `RunnerRefusal`-family types the black-box runner
  builds on. Cross-cutting exclude semantics (excludes win across every
  identity form the caller provides).
- **Terminal-safe output (1.4.10)** — `sanitize_terminal_output` strips
  C0 / DEL / Unicode C1 / CSI / OSC / 2-byte ESC sequences before
  network-derived text reaches stdout or a report body.
- **Secure artifact writes (1.4.10)** — `write_secret_artifact` +
  `SecretArtifact` enum. Unix: atomic `O_CREAT|O_EXCL + mode(0o600)`.
  Windows: `File::create_new` with parent-DACL responsibility
  documented on the caller.

## Install

```toml
[dependencies]
adhammer-core = "1.4"
```

## Example

```rust
use adhammer_core::{sanitize_terminal_output, SecretString, EngagementScope, ScopeTarget};
use std::net::IpAddr;
use std::str::FromStr;

// Terminal-safe echo of untrusted text.
let hostile = "\x1b[31m\x07spoofed";
assert_eq!(sanitize_terminal_output(hostile), "spoofed");

// Password never leaks via Debug.
let pw = SecretString::from("hunter2");
assert_eq!(format!("{pw:?}"), "***");
assert_eq!(pw.expose_secret(), "hunter2");

// Scope-driven target check with cross-cutting excludes.
let scope = EngagementScope::new(vec![ScopeTarget::Host {
    addr: IpAddr::from_str("10.0.0.10").unwrap(),
}])
.unwrap();
assert!(scope.allows_ip(IpAddr::from_str("10.0.0.10").unwrap()));
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI + orchestrator.
- [`adhammer-sdk`](https://crates.io/crates/adhammer-sdk) — pub-use façade
  over every subsystem.
- Sibling crates: `adhammer-collector`, `adhammer-checks`,
  `adhammer-graph`, `adhammer-kerberos`, `adhammer-ldap`,
  `adhammer-sysvol`, `adhammer-report`, `adhammer-bloodhound`,
  `adhammer-secrets`.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
