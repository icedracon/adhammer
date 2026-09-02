<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-kerberos</h1>

<p align="center"><em>Kerberos verbs — AS-REP roast, Kerberoast, S4U/RBCD, PKINIT, Shadow Credentials, ticket forge.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-kerberos"><img src="https://img.shields.io/crates/v/adhammer-kerberos?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-kerberos"><img src="https://img.shields.io/docsrs/adhammer-kerberos?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Kerberos protocol verbs used across ADhammer's `attack` subcommands:

- **AS-REP roast** — offline crackable AS-REP for accounts with
  `DONT_REQ_PREAUTH`.
- **Kerberoast** — request a service ticket for every account with an
  SPN; the ticket-part is offline-crackable to recover the password.
- **PKINIT** — certificate-based AS-exchange; returns the TGT AND
  optionally the plain NT hash extracted from `PAC_CREDENTIAL_INFO`
  (`WS-UNPAC-PKINIT`).
- **Shadow Credentials** — write `msDS-KeyCredentialLink` on a target,
  then AS-exchange with the injected cert to obtain the target's TGT.
- **S4U / RBCD** — constrained + resource-based constrained delegation
  chains, including the RBCD write-then-impersonate sequence.
- **Ticket forge** — Golden / Silver / Diamond variants (Diamond
  inherits real KDC timestamps + validity to drop the 10-year IOC).
- **ccache round-trip** — MIT ccache v4 codec via the sibling
  [`ccache-io`](https://crates.io/crates/ccache-io) crate.

Built on `picky-krb` for ASN.1 primitives and `picky-asn1-x509` for the
PKINIT chain.

## 1.4.10 hardening

- Outer-bound length guards on picky-krb's AES-CTS-HMAC-SHA1 decrypt
  path (`AES_MIN = 44`, `RC4_MIN = 40`) — mitigates BUG-19 (fuzz-found
  panic in `generic-array::from_slice`) at the production callsite.
- The fuzz build itself still crashes under `-C panic=abort` because
  `catch_unwind` cannot catch abort; the upstream fix (picky-krb 0.12+)
  ships in the 1.5.0 `WS-DEPS-MAJORS` workstream.

## Install

```toml
[dependencies]
adhammer-kerberos = "1.4"
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-core`](https://crates.io/crates/adhammer-core) — types.
- [`ccache-io`](https://crates.io/crates/ccache-io) — MIT ccache v4
  codec (sibling from the same author).

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
