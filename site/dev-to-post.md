---
title: "Building adhammer — a from-scratch AD security toolkit in Rust"
published: false
description: One Rust binary. 43 published protocol crates. DCE/RPC, NTLM, SMB2, Kerberos, DRSUAPI, MS-* — all from-scratch. What you can do with it and how it stays maintainable.
tags: rust, security, opensource, showdev
canonical_url:
cover_image:
---

[adhammer](https://github.com/icedracon/adhammer) is a Rust Active Directory security toolkit — one binary that scans a domain for misconfigurations, exercises the real exploitation primitives against them, and prints receipts you can hand to a customer.

The whole thing sits on a from-scratch protocol stack: DCE/RPC, NTLM, SMB2, Kerberos, DRSUAPI, MS-CRTD, MS-ICPR, and 40+ MS-* sibling crates. No wrappers around other languages' libraries, no shelling out. Ripgrep-scale dependency tree — most crates ship with five to eight direct deps.

## What you can actually do with it

Five top-level verbs. Each does one thing.

**`scan`** — collects the domain over LDAP, feeds it to a rule engine with 41 checks, spits out an HTML or JSON report. Findings score by real blast radius (`DcsyncPath`, `UnconstrainedDelegation`, `KerberoastableAdmin`, `PasswordNotRequired`, `PreWindows2000Compat`, `RbcdConfigured`, ADCS ESC1/6/7/8/10/11/15/16 template rules, and more).

```
adhammer scan --url ldaps://dc.corp.local:636 \
              --user auditor \
              --password '@file:/tmp/pw' \
              --out audit.html
```

**`attack`** — the active side. Every one is a real primitive, not a detector:

- `coerce` — PetitPotam / PrinterBug / DFSCoerce / ShadowyCoerce (typed enum picks the pipe)
- `relay` — SMB → LDAP (RBCD, Shadow Cred) or AD CS HTTP (ESC8) or ICPR (ESC11)
- `dcsync` — GetNCChanges over a sealed DRSUAPI session, single target or `--all`
- `roast` — Kerberoasting + AS-REP roasting, AES etype accepted
- `golden` / `silver` — forge TGT/service tickets from a krbtgt/service key
- `ptt` — pass-the-ticket via S4U2Self / S4U2Proxy → AP-REQ over SMB → exec
- `shadowcred` — add msDS-KeyCredentialLink → PKINIT for the target account
- `pkinit` — take a Shadow Cred key .pem, get a TGT
- `esc1` / `esc4` / `icpr-esc1` — AD CS abuse (enrol as another principal)
- `dcshadow --prep` / `--cleanup` — rogue nTDSDSA registration (LDAP path, Server 2016)
- `abuse` — LDAP writes: `add-spn`, `add-member`, `set-password`, `write-rbcd`, `add-keycred`
- `zerologon` — CVE-2020-1472 (detect-only by default, `--exploit` is opt-in)
- `badsuccessor` — CVE-2024-15671 dMSA takeover (Server 2025)
- `exec` / `wmiexec` / `atexec` / `winrm` — post-auth command execution
- `poison` — LLMNR / NBT-NS / mDNS name poisoning

**`enum`** — recon that doesn't require replication rights:

- `sessions` — MS-SRVS `NetrSessionEnum`
- `wkssvc` — MS-WKST `NetrWkstaUserEnum`
- `hku` — remote registry HKU walk → logged-on SIDs (often works without local admin)
- `samr` — user / group enum + local group membership on any DC or member
- `posture` — relay-enabler surface (SMB signing, LDAP channel binding, EPA)
- `esc` — AD CS ESC6/7/10/11/16 registry probes over MS-RRP
- `dns` — AD-integrated DNS zone dump
- `net` — network sweep across a `/24`

**`check`** — targeted rule packs (`adcs`, `posture`) that don't need a full collection pass.

**`dump`** — offline artifact extraction: `laps`, `gmsa`, `secretsdump` (SAM / SECURITY / SYSTEM hives).

## Design principles worth stating

**Nothing sensitive goes on argv.** Every `--password` resolves through a four-tier cascade:

```rust
fn resolve_secret(argv_value: &str, env_key: &str) -> Result<String> {
    // 1. --password @file:/path/to/pw
    if let Some(path) = argv_value.strip_prefix("@file:") {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read password file {path}"))?;
        return Ok(raw.trim_end_matches(['\n', '\r']).to_string());
    }
    // 2. literal (backward compat, still leaky)
    if !argv_value.is_empty() { return Ok(argv_value.to_string()); }
    // 3. $ADHAMMER_PASSWORD env var
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() { return Ok(v); }
    }
    // 4. interactive echo-off prompt (when stdin is a TTY)
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

Applies to every attack handler and every session-hunt enum. Uses `dialoguer::Password` — no new dep, no `rpassword`, no re-implementing termios.

**Bulk destructive actions gate on `--yes`.** `attack dcsync --all` and `attack samr --dump-secrets` refuse to run on a TTY without `--yes`, and both accept `--limit N` to bound blast radius during a run. Non-TTY (CI) proceeds without the gate.

**Every wire decoder preflights its allocations.** Any `Vec::with_capacity(n)` where `n` comes off the wire goes through:

```rust
let count = read_u32(d)? as usize;
if count.checked_mul(ENTRY_SIZE).map_or(true, |need| need > d.remaining()) {
    return Err(RpcError::Protocol("count exceeds remaining buffer"));
}
let mut items = Vec::with_capacity(count);
```

`checked_mul` catches `u32::MAX * 12` overflow; `.map_or(true, …)` treats overflow as an over-allocation and rejects. Hostile inputs never reach the allocator.

**Clap rejects nonsense at parse time.** Subcommands like `attack coerce`, `attack abuse`, `attack relay` take typed enums for their action selector, not free-form strings:

```
$ adhammer attack coerce --pipe totallybogus …
error: invalid value 'totallybogus' for '--pipe <PIPE>'
  [possible values: spoolss, lsarpc, efsrpc, netdfs, fssagentrpc]
```

Old free-form-string versions would open an SMB connection, negotiate DCERPC, then bail on the pipe name. Wasted round trips + a confusing error you had to read past three layers of RPC noise to find.

**Session file is DPAPI-encrypted on Windows.** On Unix it's `O_CREAT|O_EXCL` + mode `0o600` in one syscall — no umask window. Where DPAPI is unavailable the tool refuses to write in cleartext unless you opt in with `ADHAMMER_ALLOW_PLAIN_SESSION=1`.

**Global `--json` envelope** on every `attack` / `enum` / `dump` subcommand. Output pipes cleanly into `jq` and CI. `scan` emits JSON by default with `--out report.json`, or `--out report.html` for human review.

**MIT. No telemetry. Never phones home.**

## Architecture

12-crate workspace + 43 sibling protocol crates published under `icedracon` on crates.io.

```
adhammer/
├── cli/                — clap CLI, subcommands
├── crates/
│   ├── core/           — Finding, Severity, shared types
│   ├── collector/      — LDAP collection (ldap3)
│   ├── checks/         — 41 security-check rules
│   ├── graph/          — petgraph control-path chains
│   ├── kerberos/       — roasting, ticket forging
│   ├── report/         — HTML + JSON report generation
│   ├── sysvol/         — GPO / GPP / registry-pol parsing
│   ├── ldap/           — LDAP helper extensions
│   ├── bloodhound/     — BloodHound-CE JSON export
│   ├── secrets/        — SAM / SECURITY / LSA / LAPS / gMSA
│   └── sdk/            — one-import facade over all sub-crates
```

The 43 published sibling crates group into:

- **Wire foundation (5)** — `dcerpc`, `ntlmssp`, `smb2-client`, `windows-sddl`, `ms-ndr`
- **MS-* protocol clients (18)** — `ms-drsr`, `ms-icpr`, `ms-crtd`, `ms-csra`, `ms-gkdi`, `ms-pkca`, `ms-pac-forge`, `ms-dnsp`, `ms-tsch`, `ms-lsat`, `ms-coerce`, `samr`, `ms-nrpc`, `ms-tds`, `ms-kile-fast`, `ms-even6`, `ms-fve`, `ms-rodc`
- **Auth / crypto / ACL (5)** — `credssp`, `dpapi-ng`, `dpapi-offline`, `ad-acl`, `msldap-ext`
- **Offensive extras (5)** — `gpo-forge`, `preg`, `llmnr-poison`, `ntlm-relay`, `winrm-pentest`
- **Offline / DFIR (3)** — `ese-parser`, `ntds-parse`, `lsass-parse`
- **Windows platform wrappers (6)** — `windows-token`, `windows-scm`, `windows-lsa`, `windows-wmi-com`, `windows-sspi-shim`, `windows-eventlog-native`
- **BloodHound-CE export (1)** — `bloodhound-export`

Every crate is `cargo install`-able standalone. Reuse `dcerpc` in your own DFIR tool without pulling in the attack primitives. Use `ese-parser` for offline NTDS.dit forensics without any wire code. Consume `ms-icpr` to build your own CSR helper.

That "dual-use" rule is enforced: a primitive gets extracted into a sibling crate only when it has genuine defensive / admin / DFIR appeal, not just offensive. Attacker-only compositions stay in the CLI.

## From-scratch, meaning

- **DCE/RPC** — bind (unauth / NTLM / Kerberos / sealed), NDR encoder + decoder, endpoint mapper client, fault-code decoder, association-group support
- **SMB2 client** — NTLM + Kerberos auth, signing, session setup, tree connect, IOCTL, pipe transport, egress via SOCKS5
- **Kerberos** — AS-REQ / AS-REP, TGS-REQ, S4U2Self, S4U2Proxy, PKINIT (DH exchange + AS-REP decrypt), PA-PAC-OPTIONS, ccache reader/writer, AES128 / AES256 / RC4 / DES key derivation
- **MS-DRSR** — GetNCChanges, DsCrackNames, DsGetNCChangesW / X, bounded-alloc reply parser
- **MS-EFSR / MS-DFSNM / MS-RPRN / MS-FSRVP** — all four coerce vectors on the same SMB session interface
- **MS-ICPR** — ADCS certreq over HTTPS and over ncacn_ip_tcp (`\PIPE\cert` alternative endpoint)
- **MS-CRTD** — certificate template parser + ESC rule pack (ESC1/4/6/7/8/10/11/15/16)
- **MS-RRP** — remote registry, MS-EVEN6 remote event log, MS-TSCH scheduled tasks, MS-NRPC Zerologon
- **ADCS Web Enrollment** — HTTP relay with NTLM handshake and CSR forwarding on the same TCP connection

## Install

```bash
cargo install --locked adhammer
```

Rust 1.88+. Windows / macOS / Linux (tested on all three in CI).

Then:

```bash
# audit-only scan → HTML report
adhammer scan --url ldaps://dc.corp.local:636 \
              --user auditor \
              --password '@file:/tmp/pw' \
              --out audit.html

# guided attack menu (interactive TTY prompts everything)
adhammer

# CI-friendly JSON envelope on a single primitive
ADHAMMER_PASSWORD='…' \
  adhammer --json attack dcsync \
           --host dc.corp.local --domain CORP \
           --user Administrator --target krbtgt
```

## Development discipline

Every release runs the same gate:

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- CI matrix: ubuntu + windows + macos
- MSRV verify job pins the toolchain to whatever `rust-version` in `Cargo.toml` says
- Wire code validated against at least one live DC before shipping

Every hostile-length wire input has a regression test that feeds `0xFFFF_FFFF` and asserts `RpcError::Protocol` without panic or OOM. Every principal-string function has a test that feeds Cyrillic and rejects it (RFC 4120 IA5String rule).

Recent releases have been driven by outside code review — an external multi-agent reviewer runs against the diff before ship, and the findings that survive verification become the next milestone. The current release closed 33 of 37 findings from one such pass.

## Roadmap

**1.4.x** — bulk MSSQL enumeration (via `ms-tds`), Exchange abuse primitives, SCCM `NAA` extraction, DCShadow phase-2 push (RPC path, works past the 2019+ LDAP hardening), cross-forest Kerberos (S4U2Proxy across trusts), sealed LDAP bind (Windows Server 2025 channel-binding requirement), bulk DRSUAPI (parallel `GetNCChanges` across DCs).

**1.5.x** — semi-interactive shell (post-auth REPL), cross-forest attack graph, automated coerce → relay → exploit chains.

## Contribute

Issues, PRs, or a hard-critic review of your own — all welcome.

- Repo: https://github.com/icedracon/adhammer
- Crate: https://crates.io/crates/adhammer
- Changelog: https://github.com/icedracon/adhammer/blob/main/CHANGELOG.md

MIT. Written by [zevs](https://github.com/icedracon).
