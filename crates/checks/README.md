<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-checks</h1>

<p align="center"><em>Active Directory hygiene rules — privileged accounts, trusts, stale objects, anomalies, ADCS ESC set, tagged with MITRE ATT&amp;CK.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-checks"><img src="https://img.shields.io/crates/v/adhammer-checks?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-checks"><img src="https://img.shields.io/docsrs/adhammer-checks?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

The rules engine. Consumes an `adhammer_core::Snapshot` and emits a
`Vec<Finding>` covering:

- **Privileged accounts** — DA / EA / SA misuse, service-account
  Kerberoast surface, over-privileged nested groups.
- **Trusts** — outbound trust with quarantine off, SID history flow,
  cross-forest privilege leaks.
- **Stale objects** — unused computer accounts, orphan trust links,
  dangling AdminSDHolder markers.
- **Anomalies** — SPN weirdness, `msDS-AllowedToDelegateTo` shapes that
  form RBCD hops, computer objects that shouldn't be.
- **ADCS ESC set** — ESC1..ESC15 rule pack via the `esc_registry`
  module. Each rule carries the finding id, MITRE technique tag, and a
  reproducible reason string a reviewer can trace back to the raw LDAP
  attribute.

Every emitted `Finding` carries `Category` + `Severity` + `mitre` tags
and a `remediation` string. `impact` is required by the internal
"no finding without impact" contract (WS-PROOF-70).

## Install

```toml
[dependencies]
adhammer-checks = "1.4"
```

## Example

```rust
use adhammer_checks::run_all;
use adhammer_core::Snapshot;

// let snapshot: Snapshot = adhammer_collector::Collector::collect(...).await?;
// let findings = run_all(&snapshot);
// for f in findings {
//     println!("{} [{:?}] {}", f.id, f.severity, f.title);
// }
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-collector`](https://crates.io/crates/adhammer-collector) —
  produces the snapshot input.
- [`adhammer-report`](https://crates.io/crates/adhammer-report) —
  renders findings + score.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
