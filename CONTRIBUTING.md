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

## Referring to external tools

ADhammer does not pitch itself against any other tool. README, help text, blog posts, and
release notes describe **what adhammer does**, not what other tools fail to do — no
comparison tables, no "unlike X we do Y" copy, no ranking claims. Screenshots, docs, and
package metadata stay competitor-free.

There is exactly one place where external tool names DO belong in shipped output:
**`cli/src/gap_hint.rs`** and its docs sink `docs/GAPS.md`. That module emits a
copy-pasteable external command at each point where adhammer honestly does not cover a
capability — e.g. an LSASS symbol walk hands off to a specialist minidump tool, a live
BloodHound-CE collect hands off to `rusthound-ce`, an offline NTDS.dit extract hands off
to `impacket-secretsdump`. These references are **operational humility markers**, not
competitive pitches: they name the specialist so an operator can finish the job, with the
captured parameters pre-substituted so the copy-paste works from the same shell.

The distinction, so a reviewer can grade a PR against it:

- **Not allowed:** any text that positions adhammer *against* another tool, including
  README badges, feature-parity claims, "vs" tables, and "we're better because" prose.
- **Allowed:** `gap_hint.rs` entries that name a specialist tool as the recommended
  next-step for a specific capability adhammer does not implement, alongside a real
  runnable command line.
- **Also allowed:** attribution of an upstream library adhammer consumes (e.g. an
  eventual RustHound-CE library integration would get an attribution line in
  `README.md` + a licence-notice row — see `docs/PLAN_1.5.2.md`).

If you're adding a new `gap_hint.rs` entry, prefer one specialist per capability (not a
list); keep the command line runnable end-to-end with the captured parameters; and never
add a "here's how it compares" sentence — the point is "here's how to finish the job",
nothing more.
