<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-ldap</h1>

<p align="center"><em>Raw LDAP client — NTLM SASL bind + search/modify, for LDAP-389 auth and NTLM relay.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-ldap"><img src="https://img.shields.io/crates/v/adhammer-ldap?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-ldap"><img src="https://img.shields.io/docsrs/adhammer-ldap?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Minimal, from-scratch LDAP v3 client. Distinct from
`adhammer-collector`'s ldap3-based read path — this crate exists so the
NTLM relay path (`sasl_step1` / `sasl_step2`) has an LDAP client whose
authentication frames ADhammer controls end-to-end. Also handles the
LDAP-389 auth-then-write path for `attack abuse --action`
{`add-keycred`, `write-spn`, `write-dacl`, `add-member`, `rbcd-write`}.

Uses SPNEGO / NTLM through the sibling
[`ntlmssp`](https://crates.io/crates/ntlmssp) crate for the SASL flow.

## 1.4.9 SEC-1 hardening (AH-001..003)

- BER length parsing rejects indefinite lengths, non-canonical
  long-form lengths, and length octets beyond `MAX_BER_LENGTH_OCTETS = 4`.
- Every arithmetic step uses `checked_add` / `checked_mul`.
- `read_tlv_in(buf, pos, parent_end)` bounds child TLVs to the
  enclosing container.
- 16 MiB `MAX_LDAP_MESSAGE_BYTES` cap; 15 s connect / 30 s I/O
  deadlines wrap every request.
- Direct plaintext-LDAP-389 writes refused (`bind_ntlm` returns
  `Err`); the relay bind path is preserved.

## Install

```toml
[dependencies]
adhammer-ldap = "1.4"
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-collector`](https://crates.io/crates/adhammer-collector) —
  the ldap3-based read path.
- [`ntlmssp`](https://crates.io/crates/ntlmssp) — NTLMSSP + SPNEGO
  primitives (sibling crate from the same author).
- [`ntlm-relay`](https://crates.io/crates/ntlm-relay) — relay engine
  that consumes this LDAP client for the target side.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
