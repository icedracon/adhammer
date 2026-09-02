<p align="center">
  <img src="https://raw.githubusercontent.com/icedracon/adhammer/main/docs/logo.svg" alt="ADhammer" width="200"/>
</p>

<h1 align="center">adhammer-sysvol</h1>

<p align="center"><em>SYSVOL collection — GPP <code>cpassword</code> (MS14-025) recovery + <code>GptTmpl.inf</code> policy analysis.</em></p>

<p align="center">
  <a href="https://crates.io/crates/adhammer-sysvol"><img src="https://img.shields.io/crates/v/adhammer-sysvol?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://docs.rs/adhammer-sysvol"><img src="https://img.shields.io/docsrs/adhammer-sysvol?color=2ea8ff&style=flat-square" alt="docs.rs"/></a>
  <img src="https://img.shields.io/badge/MSRV-1.88-2ea8ff?style=flat-square" alt="MSRV 1.88"/>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What it is

Walks a SYSVOL tree (typically the UNC `\\<domain>\SYSVOL\...` reached
through the OS SMB redirector on a domain-joined host) and:

1. Recovers **GPP cpasswords** — Group Policy Preferences XML files
   encrypted with the Microsoft-published AES-256 key
   (`MS14-025`, KB2962486). Any authenticated user who can read
   SYSVOL can decrypt them.
2. Parses **`GptTmpl.inf`** policy blobs for weak security settings —
   default-policy signing, NTLM version, LM hash storage.

## 1.4.10 security boundary (BF-2 + BF-7)

- `decrypt_cpassword` returns `SecretString` (was `String`). A stray
  `Debug` / `Display` prints `"***"`; consumers that need the
  plaintext must call `.expose_secret()` — the crate has exactly one
  such call, in `write_dump`.
- `finding()` no longer embeds the recovered plaintext into
  `affected[]` or `evidence.value` — the report body is redacted.
- **`write_dump(hits, path)`** — the only authorized exposure site,
  writes a tab-separated dump to a 0600 file via
  `adhammer_core::write_secret_artifact`.
- Walk budgets: `SYSVOL_MAX_WALK_DEPTH = 32`,
  `SYSVOL_MAX_FILE_BYTES = 4 MiB`, `SYSVOL_MAX_HITS = 10_000`. All
  refusals log at `warn` — never silent short-return.

## Install

```toml
[dependencies]
adhammer-sysvol = "1.4"
```

## Example

```rust
use adhammer_sysvol::{scan, finding, write_dump};
use std::path::Path;

let hits = scan(Path::new(r"\\corp.local\SYSVOL"));
if let Some(f) = finding(&hits) {
    println!("{}: {}", f.id, f.title);
    // Optional: dump plaintext to 0600 file (BF-2 secure-write helper).
    // write_dump(&hits, Path::new("gpp_recovered.tsv"))?;
}
```

## Related

- [`adhammer`](https://crates.io/crates/adhammer) — the CLI.
- [`adhammer-core`](https://crates.io/crates/adhammer-core) — provides
  `SecretString` + `write_secret_artifact`.

## License

MIT — see [LICENSE](https://github.com/icedracon/adhammer/blob/main/LICENSE).
