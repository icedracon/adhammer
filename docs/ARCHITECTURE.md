# ADhammer architecture

This document describes the public architecture of ADhammer: how data moves through the project, where responsibilities live, and which boundaries contributors and integrators should preserve.

## Design goals

ADhammer is built around five constraints:

1. **Evidence first.** A discovered condition is not the same thing as a validated result. Public capability claims must remain aligned with `docs/VALIDATION.md`.
2. **Protocol-native Rust.** Core Active Directory protocol work is implemented in Rust without requiring a Python runtime or host Kerberos library.
3. **Separation of concerns.** Collection, graph analysis, checks, reporting, secrets handling, and CLI orchestration are separate layers.
4. **Bounded hostile-input handling.** Parsers and network-facing code must treat remote input as untrusted and avoid unbounded allocation or panic-driven control flow.
5. **Reusability.** Protocol and domain primitives should remain useful outside the CLI where practical.

## Data flow

```text
Target / authorized lab
        |
        v
+--------------------+
| collector / LDAP   |
| RPC / SMB / KRB    |
+--------------------+
        |
        v
+--------------------+
| normalized domain  |
| objects + evidence |
+--------------------+
        |
        +--------------------+
        |                    |
        v                    v
+--------------------+  +--------------------+
| checks             |  | graph              |
| posture/findings   |  | control paths      |
+--------------------+  +--------------------+
        |                    |
        +---------+----------+
                  |
                  v
        +--------------------+
        | report / export    |
        | JSON HTML MD BHCE  |
        +--------------------+
                  |
                  v
        operator / defender
```

Live validation flows are orchestrated by the CLI and must record enough evidence to distinguish **observed**, **validated**, and **validation owed** states.

## Workspace responsibilities

| Crate | Responsibility |
|---|---|
| `adhammer-core` | Shared domain types, scope handling, redaction, common policy primitives. |
| `adhammer-secrets` | Secret-related parsing and offline handling. |
| `adhammer-ldap` | LDAP-facing directory primitives and normalization helpers. |
| `adhammer-graph` | Control-edge representation and path analysis. |
| `adhammer-sysvol` | SYSVOL / GPO parsing and policy analysis. |
| `adhammer-kerberos` | Kerberos-facing helpers used by ADhammer workflows. |
| `adhammer-bloodhound` | BloodHound CE export compatibility layer. |
| `adhammer-checks` | Assessment logic that turns collected state into findings. |
| `adhammer-collector` | Data acquisition and discovery orchestration. |
| `adhammer-report` | Evidence-preserving report generation. |
| `adhammer-sdk` | Public integration surface for Rust consumers. |
| `adhammer` | CLI, operator workflow, command routing, and live orchestration. |

The workspace also consumes standalone icedracon protocol crates such as `dcerpc`, `smb2-client`, `ntlmssp`, `ms-ndr`, `windows-sddl`, and Microsoft-protocol-specific crates. These should remain lower-level building blocks rather than duplicating application policy from ADhammer.

## Trust boundaries

### Remote input

LDAP values, RPC responses, SMB data, Kerberos messages, DNS responses, registry data, SYSVOL content, certificates, and reportable strings are attacker-controlled inputs from the parser's point of view. Parsing code should:

- validate lengths before allocation or slicing;
- reject malformed structures with typed errors;
- avoid logging secrets or raw credential material;
- sanitize terminal and HTML-bound text;
- add regression tests for malformed inputs;
- add fuzz coverage for byte-oriented parsers when practical.

### Secret material

Secret values should cross as few layers as possible. Redaction is a default behavior, not an output-format preference. Any new path that formats, logs, serializes, or stores credentials must be reviewed as a security-sensitive change.

### Validation state

The validation ledger is a product boundary. Code existing in the tree does not by itself make a capability supported. The authoritative status is recorded in `docs/VALIDATION.md` and enforced by CI.

## Extension rules

New functionality should enter at the narrowest appropriate layer:

- protocol encoding/decoding belongs in a protocol crate;
- directory collection belongs in `adhammer-collector` or the relevant transport crate;
- new findings belong in `adhammer-checks`;
- new control relationships belong in `adhammer-graph`;
- output-only changes belong in `adhammer-report` or `adhammer-bloodhound`;
- operator-only workflow belongs in the CLI;
- reusable public APIs belong in `adhammer-sdk` only after their stability expectations are clear.

Avoid introducing a second implementation of an existing protocol stack inside the CLI.

## Validation layers

A mature change normally progresses through these layers:

1. **Unit or known-answer tests** for deterministic logic.
2. **Malformed-input / negative tests** for parser and boundary behavior.
3. **Interoperability tests** against a documented implementation or file/wire format where appropriate.
4. **Authorized live-lab validation** for behavior that depends on Windows or AD state.
5. **Sanitized receipt / evidence** recorded according to the validation policy.

External reproduction is encouraged through `docs/THIRD_PARTY_VALIDATION.md`.

## CI and release boundary

The default CI verifies formatting, warnings, workspace tests, supported feature combinations, MSRV, package metadata, dependency policy, and validation-ledger consistency. Fuzzing also runs in CI, with longer campaigns separated into the scheduled workflow.

Release artifacts are produced by `.github/workflows/release.yml`; release-specific support claims must continue to derive from the validation ledger rather than from implementation presence alone.

## Stability

Public crate and MSRV expectations are documented in `docs/STABILITY.md` and `docs/POLICY_MSRV.md`. Architecture changes that alter crate responsibilities, report schemas, public SDK behavior, or validation semantics should update this document in the same change.
