## Summary

Describe the problem and the change. Keep the scope to one logical unit.

## Why this belongs in ADhammer

Explain how the change fits Active Directory assessment, protocol infrastructure, evidence handling, reporting, or project reliability.

## Validation

Check every item that applies and describe any exceptions.

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Added or updated unit / protocol-vector tests where behavior changed
- [ ] For live behavior, validated only in an authorized lab and provided sanitized evidence
- [ ] Public capability claims remain consistent with `docs/VALIDATION.md`

## Security and privacy

- [ ] No credentials, customer data, real target identifiers, private keys, or unsanitized engagement artifacts are included
- [ ] New parsing or network-facing code handles malformed input and bounded allocation appropriately
- [ ] New dependencies are justified and kept minimal

## Compatibility

Note any effect on MSRV, feature flags, Windows Server versions, report schemas, BloodHound export, or published crate APIs.

## Related issue

Closes #
