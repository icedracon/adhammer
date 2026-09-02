<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-secrets</h1>

<p align="center"><em>Registry hive (regf) parser + bootkey + SAM / LSA / DCC2 offline secret decryption.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-secrets"><img src="https://img.shields.io/crates/v/adhammer-secrets?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-secrets"><img src="https://img.shields.io/docsrs/adhammer-secrets?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Offline Windows secret decryption from registry hive files (`SYSTEM`,
`SAM`, `SECURITY`) captured from a target's `%SystemRoot%\System32\config\`:

- **`regf` parser** — from-scratch Windows registry hive walker; no C
  interop, no third-party regf crate.
- **Bootkey extraction** — assembles the four fragments of the boot key
  from `SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}`.
- **SAM decryption** — RC4-then-DES key schedule to recover local NT
  hashes for every account.
- **LSA secrets** — `SECURITY\Policy\Secrets\*` decryption; recovers
  service-account passwords cached by the LSA.
- **DCC2** — Domain Cached Credentials v2 (MS-DCC2) — the cached hash
  used for offline logon; extractable from `SECURITY\Cache\`.

Used by ADhammer's `attack secretsdump` verb.

## Install

```toml
[dependencies]
adhammer-secrets = "1.4"
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-core`](https://crates.io/crates/adhammer-core) — provides
  `SecretString` / `SecretBytes` for the recovered material.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
