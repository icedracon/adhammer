<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-report</h1>

<p align="center"><em>Aggregation + risk scoring → JSON / HTML / Markdown / text reports.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-report"><img src="https://img.shields.io/crates/v/adhammer-report?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-report"><img src="https://img.shields.io/docsrs/adhammer-report?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Aggregates a `Vec<Finding>` + attack paths into a scored `Report` and
renders it into four formats:

- **JSON** — machine-readable; consumed by CI / SIEM / downstream
  scoring pipelines.
- **HTML** — self-contained page with light + dark themes, table of
  contents, per-category collapsibles, an optional BloodHound-style
  SVG of the top attack chain.
- **Markdown** — PDF-friendly. Every attack chain rendered as a
  `principal → [Edge] → target` line.
- **Plain text** — the `to_text_summary(n)` compact form for terminal
  echo or the operator's notes.

Scoring is configurable via `RiskConfig` — per-`Category` multipliers
default to security-sensible values (Privileged 1.5, Trusts 1.2,
Anomalies 1.0, Stale 0.5).

## 1.4.10 boundary (BF-8)

`Report::build` runs every user-facing string field of `Finding` and
`AttackPath` through `adhammer_core::sanitize_terminal_output` before
storage. A hostile LDAP attribute value that embeds ANSI CSI or an OSC
title spoof cannot re-materialize in any of the four renderers.

## Install

```toml
[dependencies]
adhammer-report = "1.4"
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-checks`](https://crates.io/crates/adhammer-checks) —
  produces the findings this crate scores + renders.
- [`adhammer-graph`](https://crates.io/crates/adhammer-graph) —
  produces the `AttackPath` set embedded in the report.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
