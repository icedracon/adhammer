<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-collector</h1>

<p align="center"><em>LDAP collection layer — domain + Configuration NC sweep, TLS via <code>ldap3</code>.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-collector"><img src="https://img.shields.io/crates/v/adhammer-collector?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-collector"><img src="https://img.shields.io/docsrs/adhammer-collector?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Pulls the object classes the checks + graph need, in paged sweeps over
the domain NC *and* the Configuration NC (where AD CS templates + CAs
live), and normalizes them into `adhammer_core::Snapshot`. Binary
attributes (`objectSid`, `nTSecurityDescriptor`, `objectGUID`, RBCD) are
requested raw so ADhammer parses them itself rather than trusting an
LDAP client's higher-level rendering.

Feature-gated TLS backend selection:

- `tls-rustls` (default) — `rustls` with bundled AWS-LC. No system
  OpenSSL; portable static builds.
- `tls-native` — OpenSSL / Schannel. Reaches legacy DCs that only offer
  SHA-1 certs.

`tls-rustls` and `tls-native` are **mutually exclusive** — a
`compile_error!` at the crate boundary fires if both activate. Ldap3
itself also refuses the combination upstream. `--all-features` is
therefore not a supported invocation on the ADhammer workspace.

## Security (1.4.10)

- **`require_bind_integrity`** — refuses an authed `simple_bind` over
  plaintext `ldap://` unless the operator opts in via
  `LdapConfig.allow_plaintext_bind = true`. LDAPS is safe. GSSAPI over
  389 is safe (SASL sealing). Anonymous binds always allowed (no
  credential in flight).
- **`LDAP_MAX_ENTRIES_PER_SEARCH = 500_000`** — hostile / broken servers
  that dribble entries forever are refused, not consumed unbounded.

## Install

```toml
[dependencies]
adhammer-collector = "1.4"     # tls-rustls default
# or:
adhammer-collector = { version = "1.4", default-features = false, features = ["tls-native"] }
```

## Example

```rust
use adhammer_collector::{Collector, LdapConfig};
use adhammer_core::SecretString;

# tokio_test::block_on(async {
let cfg = LdapConfig {
    url: "ldaps://dc.corp.local:636".into(),
    bind_dn: "CORP\\Administrator".into(),
    password: SecretString::from("hunter2"),
    base_dn: None,
    insecure: false,
    gssapi: false,
    allow_plaintext_bind: false, // secure default (1.4.10 BF-1)
};
// Collector::connect(&cfg).await? — dials LDAPS + reads the RootDSE.
# });
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI orchestrator.
- [`adhammer-core`](https://crates.io/crates/adhammer-core) — types.
- [`adhammer-checks`](https://crates.io/crates/adhammer-checks) —
  consumes the snapshot produced here.
- [`adhammer-graph`](https://crates.io/crates/adhammer-graph) — builds
  the attack-path graph from the same snapshot.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
