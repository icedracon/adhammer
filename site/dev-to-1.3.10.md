---
title: "adhammer 1.3.10 — 35 findings closed, wire-proven on 2022 + 2025 DCs"
published: false
description: A week under external code review. What broke, what got hardened, and what the fresh krbtgt hash on my terminal proves.
tags: rust, security, opensource, showdev
canonical_url:
cover_image:
---

[adhammer](https://github.com/icedracon/adhammer) is a Rust Active Directory security toolkit. From-scratch protocol stack — DCE/RPC, NTLM, SMB2, Kerberos, DRSUAPI, MS-CRTD, MS-ICPR, and 40+ MS-* sibling crates — one repo, MIT licensed, ripgrep-scale dependency tree.

Last week I put 1.3.9 in front of an outside multi-agent code reviewer with instructions to be a hard critic. It came back with 37 findings across security, wire hardening, CLI UX, arch cleanup, and CI. 33 of them shipped in 1.3.10. This post walks the ones with teeth.

## The finding that mattered most

Guided mode was leaking `--password` values into the on-disk transcript.

Reproduction: `adhammer` prints "here's the exact command I ran" at the end of every guided run. The line included every arg verbatim, including `--password Hunter2!`. The transcript then got saved to disk. On multi-user Windows lab hosts, that transcript is world-readable.

Fix: 13 sensitive flag names now route through a redact helper before the command line is rendered.

```rust
const REDACT_FLAGS: &[&str] = &[
    "--password", "--nt-hash", "--account-password",
    "--krbtgt-aes256", "--service-aes256",
    "--aes256", "--aes128", "--restore",
    "--restore-password", "--rc4",
    "--ccache-password", "--key", "--key-pem",
];

fn redacted_cmd(argv: &[String]) -> String {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    for a in argv {
        if redact_next {
            out.push("<redacted>".into());
            redact_next = false;
        } else {
            out.push(a.clone());
            if REDACT_FLAGS.iter().any(|f| a == f) {
                redact_next = true;
            }
        }
    }
    out.join(" ")
}
```

Four unit tests cover: single flag, multiple flags, flag at the end (nothing to redact after), and non-sensitive flags left alone.

## Secrets don't go on argv any more

Every subcommand that takes `--password` now resolves it through a four-tier cascade:

1. `--password @file:/path/to/pw` — read from a file, trailing `\r\n` trimmed
2. `--password foo` — literal (still supported, still leaky, still your call)
3. `$ADHAMMER_PASSWORD` env var
4. Interactive prompt with echo off (when stdin is a TTY)

Zero new dependencies — reuses `dialoguer::Password`, already pulled in for interactive mode.

```rust
fn resolve_secret(argv_value: &str, env_key: &str) -> Result<String> {
    if let Some(path) = argv_value.strip_prefix("@file:") {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read password file {path}"))?;
        return Ok(raw.trim_end_matches(['\n', '\r']).to_string());
    }
    if !argv_value.is_empty() {
        return Ok(argv_value.to_string());
    }
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() { return Ok(v); }
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let pw = dialoguer::Password::new()
            .with_prompt(format!("password (or set {env_key})"))
            .interact()?;
        return Ok(pw);
    }
    Ok(String::new())
}
```

Live-validated end-to-end on a real DA credential:

```
$ adhammer attack dcsync --host 10.0.0.20 --domain LAB \
    --user Administrator --password '@file:/tmp/pw' --target krbtgt
krbtgt:502:aad3b435...:XXXX...XXXX:::
krbtgt:aes256-cts-hmac-sha1-96:XXXX...XXXX
```

That's the full path: file read → resolver → NTLM inside DCERPC → DRSUAPI GetNCChanges → krbtgt hash. Every hop exercised.

## Wire hardening

Three bounded-alloc preflights landed in DRSUAPI reply parsing (`ptmc`, `amc`, `vmc` sections). The pattern:

```rust
let count = read_u32(d)? as usize;
if count.checked_mul(ENTRY_SIZE).map_or(true, |need| need > d.remaining()) {
    return Err(RpcError::Protocol("count exceeds remaining buffer"));
}
let mut items = Vec::with_capacity(count);
```

`checked_mul` catches `u32::MAX * 12` overflow; the `.map_or(true, ...)` treats overflow as an over-allocation and rejects. Every attacker-controlled length feeds through this gate before `Vec::with_capacity` sees it.

Same file: `read_dsname_rid` was doing an unchecked slice + `.unwrap()` on `SubAuthorityCount`. A crafted SID with count 0 or > 5 (spec-invalid) would panic. Now:

```rust
anyhow::ensure!(
    (1..=5).contains(&sub_auth_count),
    "SubAuthorityCount out of RFC range: {sub_auth_count}"
);
let off = 8 + 4 * (sub_auth_count - 1) as usize;
let raw = d.get(off..off + 4)
    .ok_or_else(|| anyhow!("SID buffer too short"))?;
```

Kerberos got the same treatment. `krb_string`, `principal`, and `build_as_req` used to panic inside `picky-asn1` when handed non-IA5String input (anything non-ASCII). RFC 4120 requires IA5String for principal components. All three now return `Result` and reject non-ASCII at the boundary:

```rust
fn krb_string(s: &str) -> Result<KerberosStringAsn1> {
    if !s.is_ascii() {
        anyhow::bail!("non-ASCII in Kerberos principal component: {s:?}");
    }
    KerberosStringAsn1::from_string(s.to_string())
        .map_err(|e| anyhow!("kerberos string encode: {e}"))
}
```

Regression tests feed Cyrillic and Chinese input; both return `Err` without panic.

The registry hive walker got rewritten from recursive to iterative. A crafted `ri` (root-index) block with a cyclic subkey list could stack-overflow the original. Now it's a `VecDeque` BFS with a `HashSet<u32>` cycle guard and a `MAX_VISITED = 65_536` cap:

```rust
let mut queue: VecDeque<u32> = VecDeque::from([root]);
let mut seen: HashSet<u32> = HashSet::new();
let mut out = Vec::new();
while let Some(off) = queue.pop_front() {
    if !seen.insert(off) { continue; }
    if seen.len() > MAX_VISITED { break; }
    // ... walk children into queue ...
}
```

## CLI now rejects nonsense at parse time

Three subcommands were taking free-form strings for what should have been typed enums:

- `attack coerce --pipe <spoolss|lsarpc|efsrpc|netdfs|fssagentrpc>`
- `attack abuse --action <add-spn|add-member|set-password|add-keycred|write-rbcd|pkinit>`
- `attack relay --target <ldap-keycred|ldap-rbcd|adcs-http|icpr>`

Old behavior: `--pipe totallybogus` would open an SMB connection to the target, log in, negotiate DCERPC, then bail on the pipe name. Wasted round trips + a confusing error you had to read past three layers of RPC noise to find.

New:

```
$ adhammer attack coerce --pipe totallybogus ...
error: invalid value 'totallybogus' for '--pipe <PIPE>'
  [possible values: spoolss, lsarpc, efsrpc, netdfs, fssagentrpc]
```

Implementation is one `#[derive(clap::ValueEnum)]` per subcommand plus swapping `String` for the enum type on the arg field. Clap's default kebab-case rename maps every variant byte-for-byte to the old string, so every existing invocation still parses.

One naming collision worth documenting: `attack relay` already had an internal data-carrying `enum RelayTarget` at line 2985 (variants like `AdcsHttp(String, u16, String, bool)`). The new clap value_enum wanted the same name. Rename the internal to `RelayAction`, keep `RelayTarget` for the CLI selector. Compiler catches every reference site.

## Session file, 0600 atomic

The saved-session file (`~/.config/adhammer/session.json`) previously existed briefly at umask default before `set_permissions(0600)` fixed it. Race window on any multi-user Linux/BSD host. Now it's created via `O_CREAT|O_EXCL` + mode `0o600` in one syscall:

```rust
let mut f = std::fs::OpenOptions::new()
    .write(true).create_new(true).mode(0o600)
    .open(&path)
    .with_context(|| format!("open {} 0600", path.display()))?;
f.write_all(&blob)?;
f.sync_all()?;
```

Also: non-Windows hosts where DPAPI is unavailable now refuse to write the session in cleartext unless `ADHAMMER_ALLOW_PLAIN_SESSION=1` is set. Previous behavior silently wrote plaintext under a magic-header prefix that read `"DPAPI-encrypted"` — a marketing lie.

## CI got teeth

- Clippy is now gated as `-D warnings` (was `|| true` — anything went)
- Test matrix runs on ubuntu / windows / macos (was ubuntu-only)
- MSRV verify job reads `rust-version` from `Cargo.toml` and pins the toolchain

## The receipts

Built a two-DC Windows lab (2025 + 2022, both testlab.local NetBIOS but separate forests) and ran the full 1.3.10 wire surface against both before shipping:

| test | 2025 DC | 2022 DC |
|---|:---:|:---:|
| `dcsync krbtgt` (bounded-alloc DRSUAPI) | pass | pass |
| `coerce --pipe spoolss` (typed enum, wire) | pass | pass |
| `coerce --pipe totallybogus` (clap gate) | pass | pass |
| `enum sessions` with env fallback | pass | pass |
| `dcsync --all --yes --limit 3` | pass | pass |

Bounded-alloc DRSUAPI did not reject a single real DC response. `@file:` cascade worked end-to-end on real DA creds. clap gate produced the expected UX on bad input. Real krbtgt AES256 came back on both DCs.

## What's on 1.4.0

The four findings that didn't fit — refactors, no user-visible change, all deferred cleanly:

- `arch-0` — split `cli/src/main.rs` (~5500 lines) into a `crates/attacks/` sub-crate
- `arch-1` — extract `adcs_relay.rs` into a standalone `ntlm-relay` sub-crate
- `ux-0` / `ux-2` — shape-family shared arg structs (`SmbAuth`, `LdapAuth`, `OptAuth`) across ~20 subcommands
- `ux-7` — grouped interactive menu (categories: recon / creds / lateral / persist)

Plus the always-on 1.4.x backlog: MSSQL enumeration, Exchange, SCCM, DCShadow phase-2 push, bulk DRSUAPI, cross-forest Kerberos, sealed LDAP bind.

## Install

```bash
cargo install --locked adhammer
```

Then:

```bash
adhammer scan --url ldaps://dc.corp.local:636 \
              --user auditor \
              --password '@file:/tmp/pw' \
              --out audit.json
```

MIT. No telemetry. `--yes` gate on any bulk destructive action.

## Links

- Repo: https://github.com/icedracon/adhammer
- Crate: https://crates.io/crates/adhammer
- Changelog: https://github.com/icedracon/adhammer/blob/main/CHANGELOG.md

Written by [zevs](https://github.com/icedracon). Feedback welcome — issues, PRs, or a hard-critic review of your own.
