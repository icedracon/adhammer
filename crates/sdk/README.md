<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-sdk</h1>

<p align="center"><em>The AD audit + offensive toolkit as one importable SDK — pub-use façade over every subsystem.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-sdk"><img src="https://img.shields.io/crates/v/adhammer-sdk?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-sdk"><img src="https://img.shields.io/docsrs/adhammer-sdk?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

ADhammer is split into **Core** (the reusable libraries under
`crates/*`) and the **CLI** (the `adhammer` binary that drives them).
This crate is the single import surface for Core: a downstream tool
can

```toml
[dependencies]
adhammer-sdk = "1.4"
```

and then `use adhammer_sdk::{graph, kerberos, sysvol, …}` instead of
depending on each `adhammer-*` crate individually.

Re-exported subsystems, bottom-up:

- [`types`](../core/README.md) — core types (`Sid`, `Guid`, `Snapshot`,
  `Finding`, `SecretString`).
- [`collector`](../collector/README.md) — LDAP collection.
- [`checks`](../checks/README.md) — AD hygiene rules.
- [`graph`](../graph/README.md) — control-path graph + attack chains.
- [`kerberos`](../kerberos/README.md) — Kerberos verbs.
- [`ldap`](../ldap/README.md) — raw LDAP client (relay path).
- [`sysvol`](../sysvol/README.md) — GPP + policy analysis.
- [`bloodhound`](../bloodhound/README.md) — BloodHound CE v5 export.
- [`secrets`](../secrets/README.md) — offline SAM / LSA / DCC2.
- [`report`](../report/README.md) — JSON / HTML / MD / text reports.

## 1.4.10 additions

- **`blackbox`** module — `BlackBoxRunner`, `RunPolicy`,
  `ConsentPolicy`, `CheckSelection`, `RunSummary`, `RunnerRefusal`.
  Runner control-plane with `max_hosts` / `max_duration_secs`
  enforcement, PostCred capability gating, and cross-cutting scope
  excludes. The observable no-cred assessment capability the runner
  supports lands in 1.5.0 (`WS-FOUNDATION-BLACKBOX-CLI` +
  `WS-FOUNDATION-DNS-HANDROLL`).

## Example

```rust
use adhammer_sdk::types::{EngagementScope, ScopeTarget};
use adhammer_sdk::{BlackBoxRunner, RunPolicy, ConsentPolicy, CheckSelection};
use std::net::IpAddr;
use std::str::FromStr;

let scope = EngagementScope::new(vec![ScopeTarget::Host {
    addr: IpAddr::from_str("10.0.0.10").unwrap(),
}])
.unwrap();
let runner = BlackBoxRunner::new(
    RunPolicy {
        scope,
        consent: ConsentPolicy { allow_impact: false, allow_spoof: false, interactive: false },
        max_hosts: Some(1),
        max_duration_secs: Some(3600),
    },
    CheckSelection::default(),
);
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI itself
  (has its own README with quick-start + full verb table).
- Sibling from-scratch protocol crates (same author):
  [`dcerpc`](https://crates.io/crates/dcerpc),
  [`smb2-client`](https://crates.io/crates/smb2-client),
  [`ntlmssp`](https://crates.io/crates/ntlmssp),
  [`windows-sddl`](https://crates.io/crates/windows-sddl),
  [`ccache-io`](https://crates.io/crates/ccache-io),
  [`ms-icpr`](https://crates.io/crates/ms-icpr), and 20+ others.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
