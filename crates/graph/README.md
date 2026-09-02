<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-graph</h1>

<p align="center"><em>Control-path graph — cheapest-path attack chains to Tier-0 (built on <code>petgraph</code>).</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-graph"><img src="https://img.shields.io/crates/v/adhammer-graph?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-graph"><img src="https://img.shields.io/docsrs/adhammer-graph?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Turns an AD snapshot into a directed control graph and finds the
cheapest walkable path from any principal to a Tier-0 target
(`Domain Admins`, `Enterprise Admins`, `krbtgt`, an EA-equivalent).

Every edge names the primitive that walks it (`GenericAll`, `WriteDACL`,
`AddKeyCredential`, `AllowedToDelegateTo`, `MemberOf`, `AddSelf`,
`WriteSPN`, `AddMember`, …); every path knows the CLI invocation that
tries to walk it, so an operator can go from "here's the chain" to
"here's the shell that fires it" without re-typing.

Consumers include the `adhammer-report` crate (renders the top-N paths
into JSON/HTML/Markdown) and the CLI itself (surfaces the chain in
`scan` output).

## Install

```toml
[dependencies]
adhammer-graph = "1.4"
```

## Example

```rust
use adhammer_graph::{AttackPath, ControlGraph, EdgeKind};

// ControlGraph::from(&snapshot) builds every AD-side control edge from
// object ACEs, group memberships, delegation flags, and dMSA principals.
// Then find_cheapest_paths_to_tier0() enumerates walkable chains.
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-collector`](https://crates.io/crates/adhammer-collector) —
  produces the snapshot this crate consumes.
- [`adhammer-report`](https://crates.io/crates/adhammer-report) —
  renders `AttackPath` into report body + BloodHound-style SVG.
- [`adhammer-bloodhound`](https://crates.io/crates/adhammer-bloodhound)
  — export the graph in BloodHound CE v5 JSON.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
