# ADR-0001: Zeroize byte-material secrets on Drop

**Status:** Accepted · 2026-08-31 · 1.4.9
**Deciders:** icedracon maintainer
**Supersedes:** —
**Superseded by:** —

## Context

`adhammer_core::Redacted<T>` (added in 1.4.7) hides secret material from
`Debug`/`Display` output and gates all reads through a greppable
`.expose()` escape hatch. That closes the accidental-log-leak class of
bug (a `tracing::debug!("{cfg:?}")` no longer prints an NT hash).

It does **not** address the *residual-memory* class:
- Rust's `Vec<u8>` drop only deallocates; the freed pages keep the
  secret bytes until the allocator reuses them.
- A core dump captured after a crash may still contain plaintext keys.
- Adjacent-heap read primitives (a downstream RCE, an OOB read bug in
  another crate we depend on) can pull the still-resident bytes.

The 1.4.8 audit called this out explicitly:

> Wrap every `Redacted<Vec<u8>>` / `Redacted<[u8; N]>` in
> `zeroize::Zeroizing`. Runtime cost negligible; adds "keys erased on
> drop" property that formal auditors expect.

## Decision

Add a `SecretBytes` newtype in `adhammer_core::redact` that:

- Wraps a `Vec<u8>`.
- Implements `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` via
  RustCrypto's `zeroize` derive.
- Serializes/deserializes transparently (matches existing `Redacted<T>`
  serde behaviour).
- Hides via the same `***` `Debug` impl as `Redacted<T>`.

Compose with `Redacted<SecretBytes>` for the print-hiding + zero-on-drop
combination. Convenience constructor `Redacted::new_zeroize(v: Vec<u8>)`
returns the composed type.

`Redacted<Vec<u8>>` still works — it just doesn't erase on drop. Keeping
both variants means existing code doesn't break on the type change, and
new code opts in explicitly via `new_zeroize`.

## Consequences

**Positive:**
- Formal auditors' "secrets erased on drop" checklist item satisfied.
- Core dumps captured after a `secretsdump` / `dcsync` verb no longer
  contain plaintext master keys / NT hashes in the freed regions.
- `zeroize` is single-purpose, no-std-friendly, RustCrypto-maintained;
  adds ~5 kB to the binary and one transitive dep.
- Compile-time trait bound on `Zeroize + ZeroizeOnDrop` is asserted in
  `redact::tests::secret_bytes_zeroize_on_drop_reference_check`, so
  future refactors can't silently drop the property.

**Negative:**
- Byte-slice-consuming call sites see `SecretBytes::as_slice()` instead
  of `Vec<u8>::as_slice()`. Trivial migration; every consumer already
  goes through `.expose()`.
- `Clone` on `SecretBytes` produces a second allocation that is ALSO
  zero-on-drop. This is the correct behaviour; noted here so nobody
  "optimizes" it away.

## Migration plan

- 1.4.9: `SecretBytes` shipped; no forced migration.
- 1.5.0: audit every `Redacted<Vec<u8>>` / `Redacted<[u8; N]>` /
  `Redacted<String>` for whether it holds byte material long enough to
  warrant erasure; migrate the "yes" set. Sites in scope:
  `adhammer_kerberos::pkinit::PkinitTgt` (`ccache`, `session_key`),
  `adhammer_kerberos::Tgt` (session key), `adhammer_cli::session` DPAPI
  seal buffers, DPAPI master-key output holder in `attack
  dpapi-master-key`.
- 2.0: consider deprecating `Redacted<Vec<u8>>` without erasure — force
  every consumer to opt in to erasure OR to `.into_inner()` a
  short-lived form.

## Related

- The `zeroize` crate: <https://crates.io/crates/zeroize>
- 1.4.8 audit § 07 (Cryptography), the paragraph flagging Redacted<T>
  as "well-designed but without Drop-erase".
- SECURITY.md § "Cryptographic key material" — the operator-facing
  description of secret handling.
