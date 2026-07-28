# Contributing to ADhammer

Thanks for your interest. ADhammer is a from-scratch Rust implementation of the AD protocol
stack (DCE/RPC, NTLM, SMB2, Kerberos) plus an audit + offensive layer on top. Contributions
that keep that stack correct, tested, and dependency-light are very welcome.

## Ground rules

- **Authorized-use only.** By contributing you agree the project's capabilities are for
  authorized testing, research, and education (see [SECURITY.md](SECURITY.md)). Do not submit
  code, logs, or fixtures containing real credentials, hostnames, IPs, or data from systems
  you do not own. Use placeholders (`corp.local`, `CORP\user`, `10.0.0.0/24`).
- **From-scratch ethos.** The protocol/crypto/marshaling layers are hand-rolled and unit-tested
  against spec vectors. Prefer adding a spec-vector or round-trip test over pulling in a heavy
  dependency.
- **No secrets in git.** `.gitignore` blocks `*.whl`, venvs, `*.ccache`, `*.key.pem`, etc.
  Keep it that way.

## Before opening a PR

```sh
cargo fmt --all
cargo clippy --workspace
cargo test --workspace          # hermetic unit tests (no network)
```

Live integration tests in `cli/tests/integration.rs` are `#[ignore]`d and require a lab DC;
they run via `ADH_DC=… ADH_PASS=… cargo test --test integration -- --ignored`. If your change
touches an offensive flow, describe how you validated it (a lab run, a captured packet, a spec
reference).

## Commit style

- One logical change per commit; imperative subject line, a body explaining the *why*.
- Match the surrounding code's style and comment density. Comment the non-obvious *why*, not
  the *what*.

## Scope

New attack primitives should sit on the existing crates (`dcerpc`/`ntlm`/`smb`/`kerberos`)
rather than adding parallel implementations. Open an issue to discuss larger additions
(new MS-RPC interfaces, new ADCS ESC classes) before investing in a big PR.
