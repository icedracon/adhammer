# Documentation index

This directory contains the public engineering and validation documentation for ADhammer.

## Core references

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component boundaries, data flow, trust boundaries, and extension rules.
- [`VALIDATION.md`](VALIDATION.md) — authoritative capability and validation ledger.
- [`THIRD_PARTY_VALIDATION.md`](THIRD_PARTY_VALIDATION.md) — how external researchers can submit independently reproduced evidence.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — security assumptions and threat model.
- [`STABILITY.md`](STABILITY.md) — crate and API maturity expectations.
- [`POLICY_MSRV.md`](POLICY_MSRV.md) — minimum supported Rust version policy.

## Release engineering

- [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) — release gates.
- [`REPRODUCIBLE_BUILDS.md`](REPRODUCIBLE_BUILDS.md) — reproducibility model.
- [`SIGNING_ROTATIONS.md`](SIGNING_ROTATIONS.md) — signing and token rotation record.
- [`BENCHMARKS.md`](BENCHMARKS.md) — benchmark methodology and results.

## Product and control coverage

- [`CONTROL_AREAS.md`](CONTROL_AREAS.md) — assessment/control-area mapping.
- [`../VECTORS.md`](../VECTORS.md) — operator-facing capability inventory.

## Historical planning documents

Files named `PLAN_<version>.md` are retained as historical release-planning records. They are not the source of truth for current capability claims. Current support status always comes from [`VALIDATION.md`](VALIDATION.md), while released changes are recorded in [`../CHANGELOG.md`](../CHANGELOG.md).

When a planning document conflicts with current implementation or validation state, the validation ledger and release notes take precedence.
