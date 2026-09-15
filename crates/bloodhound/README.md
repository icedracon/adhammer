<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-bloodhound</h1>

<p align="center"><em>BloodHound CE ingest JSON export (users / computers / groups / domains + ACE edges).</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-bloodhound"><img src="https://img.shields.io/crates/v/adhammer-bloodhound?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-bloodhound"><img src="https://img.shields.io/docsrs/adhammer-bloodhound?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Turns an `adhammer_core::Snapshot` into a BloodHound Community Edition
ingest bundle — one JSON per object class (users, computers, groups,
domains, GPOs, containers, OUs) plus the ACE-edge list. The bundle is
directly loadable via the BloodHound CE web UI's "Ingest" action,
letting an operator use ADhammer as the collector and BloodHound as the
graph-navigation UI.

The built-in exporter emits `meta.version = 5`; BloodHound CE 5.x and
6.x both accept v5 bundles. The opt-in `rusthound-ce` cargo feature
plugs the g0h4n/RustHound-CE collector (currently v2.5.13) in over the
same LDAP session and writes a `meta.version = 6` bundle for callers
that want the newer schema.

## Install

```toml
[dependencies]
adhammer-bloodhound = "1.5"
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI (invokes
  this via `--bloodhound-out <path>` on the `scan` verb).
- [`adhammer-collector`](https://crates.io/crates/adhammer-collector) —
  produces the snapshot.
- [`adhammer-graph`](https://crates.io/crates/adhammer-graph) — the
  in-tool alternative to BloodHound.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
