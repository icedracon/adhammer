# ADhammer

[![CI](https://github.com/icedracon/adhammer/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/adhammer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/icedracon/adhammer?sort=semver)](https://github.com/icedracon/adhammer/releases)
[![crates.io](https://img.shields.io/crates/v/adhammer.svg)](https://crates.io/crates/adhammer)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An **Active Directory security-assessment** toolkit in Rust: a PingCastle-class auditor that maps
a domain's attack paths — scored, graphed, and MITRE-tagged — then, for authorized red-team and
research use, **proves** those paths end-to-end. One static binary, from Kali/Linux or Windows, on
an embedded from-scratch DCE/RPC · NTLM · SMB2 · Kerberos stack (the "impacket for Rust" that
didn't otherwise exist).

Built as security research (ITMO); sibling to a Windows kernel 0-day disclosed to Microsoft MSRC.
For **authorized engagements, red-team validation, and education** only.

> **Authorized use only.** The validation modules implement working offensive techniques (DCSync,
> golden/silver tickets, pass-the-ticket, NTLM relay, ADCS abuse, RCE). Use ADhammer only against
> systems you own or are explicitly authorized to test. See [SECURITY.md](SECURITY.md).

📝 **Write-up:** [I built a full AD pentest + audit tool in Rust — on a protocol stack I wrote from scratch (no impacket)](https://dev.to/pumadracon/i-built-a-full-active-directory-pentest-audit-tool-in-rust-on-a-protocol-stack-i-wrote-from-fl5)

### 🆕 What's new in v1.3.1

- **BadSuccessor (Server 2025 dMSA)** — end-to-end working. `attack badsuccessor` creates a delegated MSA that inherits the victim's PAC on the next TGT (Yuval Gordon / Akamai). ADhammer is the only Rust implementation. `48 ms` on a live 2025 DC.
- **12× perf across every small-request path** — `TCP_NODELAY` on all SMB/RPC dials (Nagle was adding up to 40 ms per sealed opnum). RRP `secretsdump` `1083 → 91 ms`, SAMR enum `225 → 63 ms`, RBCD write `80 → 49 ms`. Inherited automatically via [`smb2-client 0.2.1`](https://crates.io/crates/smb2-client).
- **Bench matrix rebuilt on a live Server 2025 Standard DC** — 11 wins vs impacket/certipy/bloodyAD/NetExec + 1 exclusive (BadSuccessor has no Python-toolkit implementation). See table below.
- **New companion crate releases:** [`dcerpc 0.2.1`](https://crates.io/crates/dcerpc) (RRP full parity + `srvsvc`/`fsrvp`/`dfsnm` protocol modules), [`ms-ndr 0.1.0`](https://crates.io/crates/ms-ndr), [`ms-drsr 0.1.0`](https://crates.io/crates/ms-drsr), [`dpapi-ng 0.1.1`](https://crates.io/crates/dpapi-ng) (added `rpc` feature for encrypted LAPS/gMSA/dMSA blobs).

Full notes: [Releases → v1.3.1](https://github.com/icedracon/adhammer/releases/tag/v1.3.1).

![ADhammer command surface on Kali Linux: help, the offensive attack modes, enum (incl. ESC-registry + relay posture), and Zerologon safe-detection — one Rust binary](docs/tour.gif)

*Built and run on **Kali Linux** — a clean `git clone` + `cargo build` (cargo 1.95, ~38s) with 100+ unit tests green. Every screen above is real `--help` output from the compiled binary.*

## How it works

**1 — Audit.** ADhammer collects a domain over LDAP as a low-privileged user (via the `SD_FLAGS`
control), builds a BloodHound-style control-path graph in-process, and runs **41 checks** across
the four PingCastle categories — including **15 of the 16 AD CS ESC classes**, ADIDNS exposure,
and SYSVOL/GPP — scoring and MITRE-tagging every finding, exportable to BloodHound.

**2 — Validate.** A report shouldn't say a path *might* be exploitable. On its native protocol
stack ADhammer implements the matching tradecraft — Kerberos roasting, coercion, RBCD, Shadow
Credentials, DCSync, golden/silver tickets, pass-the-ticket, LAPS read, WinRM/SVCCTL exec, ADCS
enrollment — each **live-validated against a fully-patched Windows Server 2025 DC**.

![ADhammer live attack chain from Kali against a Windows DC: audit the relay-posture, safely detect Zerologon, DCSync the krbtgt key, then forge a golden ticket and pass-the-ticket over SMB to SYSTEM](docs/demo.gif)

*One Rust binary on Kali, live against a Windows DC: **audit** the DC's NTLM-relay posture → **safely detect Zerologon** (CVE-2020-1472, no reset) → **DCSync** the krbtgt key → **forge a golden ticket** → **pass-the-ticket** over SMB to code-exec as `NT AUTHORITY\SYSTEM`. The same tradecraft is live-validated against a fully-patched **Server 2025** DC (see the [write-up](https://dev.to/pumadracon/i-built-a-full-active-directory-pentest-audit-tool-in-rust-on-a-protocol-stack-i-wrote-from-fl5)).*

## Why ADhammer

|                       | **ADhammer**                          | PingCastle          | impacket / Rubeus          |
|-----------------------|---------------------------------------|---------------------|----------------------------|
| Language              | Rust — one static binary              | C# (.NET)           | Python / C#                |
| Runs from             | Kali/Linux **and** Windows            | Windows only        | Linux (impacket) / Windows |
| Passive AD audit      | ✅ 41 checks + control-path graph      | ✅ (the reference)   | ❌                          |
| Validation / offense  | ✅ roast·DCSync·tickets·relay·RCE      | ❌ (audit only)      | ✅ (offense only)           |
| Protocol stack        | from-scratch, no impacket dependency  | .NET libs           | mature, batteries-included |
| Runtime               | none (pure-Rust crates)               | .NET runtime        | Python runtime             |
| Live-validated on     | **Windows Server 2025** (patched) **+ Server 2022** | broad     | broad                      |

The niche: **audit and validation in one Linux-native binary**, on a self-rolled stack whose
security-descriptor parser, ACL semantics, NDR marshaler, and RPC/NTLM/SMB layer are reusable Rust
crates that didn't previously exist — all published under [`icedracon`](https://crates.io/users/icedracon):
[`windows-sddl`](https://crates.io/crates/windows-sddl),
[`ad-acl`](https://crates.io/crates/ad-acl),
[`ntlmssp`](https://crates.io/crates/ntlmssp),
[`ms-ndr`](https://crates.io/crates/ms-ndr),
[`smb2-client`](https://crates.io/crates/smb2-client),
[`dcerpc`](https://crates.io/crates/dcerpc),
[`dpapi-ng`](https://crates.io/crates/dpapi-ng),
[`ms-dnsp`](https://crates.io/crates/ms-dnsp),
[`preg`](https://crates.io/crates/preg).

### Head-to-head timings vs impacket / certipy / bloodyAD / NetExec

Full comparison + methodology in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md). Wall-clock, live Windows Server 2025 DC (`testlab.local`, LDAPS via enterprise CA), Python tools via SOCKS5-over-SSH tunnel so both sides travel the same network path. `—` = tool does not implement that scenario.

| Scenario | ADhammer | impacket | certipy | bloodyAD | NetExec | Winner |
|---|---:|---:|---:|---:|---:|:---|
| Zerologon (CVE-2020-1472) safe-detect | **54 ms** | — | — | — | 7779 ms | 🏆 adhammer · 144× |
| AD CS enumeration | **67 ms** | — | 5997 ms | — | — | 🏆 adhammer · 89.5× |
| ADCS ESC1 enrollment (spoofed UPN) | **315 ms** | — | 9793 ms | — | — | 🏆 adhammer · 31.1× |
| Full LDAP audit + graph + checks | **88 ms** | — | — | — | 2058 ms | 🏆 adhammer · 23.4× |
| LDAP query (name → SID) | **59 ms** | — | — | 627 ms | — | 🏆 adhammer · 10.6× |
| BadSuccessor (Server 2025 dMSA) | **48 ms** | — | — | — | — | 🏆 adhammer · only impl |
| SAMR user enumeration | **63 ms** | 310 ms | — | — | 898 ms | 🏆 adhammer · 4.9× |
| DCSync `krbtgt` (AES256 extract) | **73 ms** | 335 ms | — | — | 9058 ms | 🏆 adhammer · 4.6× |
| RBCD write | **49 ms** | — | — | 363 ms | — | 🏆 adhammer · 7.4× |
| Kerberoast (SPN + TGS harvest) | **79 ms** | 234 ms | — | — | 5847 ms | 🏆 adhammer · 3.0× |
| AS-REP Roast | **80 ms** | 220 ms | — | — | 1964 ms | 🏆 adhammer · 2.8× |
| Remote SAM+LSA secretsdump (RRP) | 74 ms | **45 ms** | — | — | — | 🥈 impacket · 1.6× |

**11/12 wins + 1 exclusive (BadSuccessor — no Python equivalent yet).** The one loss is honest — both tools use the same MS-RRP path (adhammer's SAM+LSA-via-WINREG matches impacket byte-for-byte; NT hashes verified identical). After enabling `TCP_NODELAY` on the transport socket the gap collapsed from 4.9× to 1.6×; fire-and-forget `CloseKey` (SMB WRITE instead of TRANSCEIVE) is the next optimization and should reach parity. On a DC, `attack dcsync` covers domain creds and wins anyway. Python interpreter cold-start dominates the small Python-tool times; ADhammer's Rust binary skips it, and the saving compounds when you chain 3+ ops in one engagement.

## Install

```sh
cargo install adhammer          # or: git clone … && cargo build --release
```

The default build is **pure-Rust** (rustls) — no OpenSSL, no system libraries — so it
**cross-compiles cleanly and static-links** (e.g. a fully static `x86_64-unknown-linux-musl`
binary you can drop on any Linux box):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

**Legacy DCs (SHA-1 LDAPS certs):** rustls refuses SHA-1 handshake signatures, so for those hosts
build with the native-TLS backend (OpenSSL/Schannel) instead:

```sh
sudo apt-get install -y build-essential pkg-config libssl-dev   # Debian/Kali
cargo build --release --no-default-features --features tls-native
```

Prebuilt binaries: [Releases](https://github.com/icedracon/adhammer/releases). Requires Rust 1.80+.

## Usage

Run `adhammer` with no arguments for the **guided interactive menu**: it asks for user → password
(or NT hash) → domain → DC, saves the session, then walks every action with prompts. For
golden/silver/pass-the-ticket it **auto-fetches** the krbtgt/service AES256 key (via DCSync) and the
domain SID (via LSAT) from your session — no pasting keys or SIDs. Add `--no-save` to keep creds off
disk, or "Wipe saved session" from the menu.

![ADhammer first run: the setup wizard (user → password → domain → DC), then the full 31-action guided menu — audit, enum, and every attack in one keyboard-driven list](docs/interactive.gif)

Long-running steps show a live spinner with an elapsed timer; styling auto-disables when output is
piped (so `scan` JSON and logs stay clean — `NO_COLOR` / `CLICOLOR_FORCE` honored).

Power-user subcommands:

```
scan                                        passive audit → JSON/HTML (+ --sysvol, --bloodhound out.zip)
auto                                         guided: scan → confirm each weakness → validate + PoC report
enum   {samr, lsa, net, dns, adcs, esc, posture, sessions}
                                            RPC / net / ADIDNS / AD-CS / ESC-registry / DC-posture / SRVSVC
attack {roast, spray, abuse, coerce, rbcd, constrained, unconstrained, dcsync, exec, atexec, wmiexec,
        secretsdump, gmsa, laps, esc1, esc4, golden, silver, pth, asktgt, winrm, capture, poison,
        relay, zerologon, shadowcred, dcshadow, badsuccessor}
```

**Server 2025 dMSA succession (BadSuccessor):** `attack badsuccessor --dmsa-name pwn --target <victim>` creates a delegated MSA that inherits the victim's PAC on the next TGT — Yuval Gordon / Akamai 2025. **ADhammer is the only Rust implementation.**

**Guided mode** (`adhammer auto`, or the interactive "Guided" menu): runs the audit, then walks
each finding — colored, severity-coded — asking *"validate and capture a PoC?"*. On yes it runs the
matching attack, and marks the finding **validated only when the real proof is present** (an actual
`$krb5tgs$`/`$krb5asrep$` hash, a replicated `krbtgt` secret, an `ISSUED` cert) — otherwise honestly
"attempted." It also runs opportunistic **active checks** beyond the passive scan (LAPS local-admin
read, AD CS ESC8 web-enrollment probe), adding them only if a weakness is confirmed. Everything —
validated, attempted, declined, and potential — lands in a **Markdown assessment report** with the
exact command + captured evidence per PoC. `--yes` runs it unattended.

![ADhammer guided output: severity-coded finding cards (CRITICAL DCSync control path, ESC1, Kerberoast, AS-REP, MachineAccountQuota) each validated with a captured PoC, ending in a 13-finding summary](docs/vulns.gif)

*Real `auto` output from the `testlab.local` DC assessment — 13 findings, 4 confirmed with a live PoC (full report: [auto-report.md](auto-report.md)).*

Validators: Kerberoast · AS-REP · DCSync · gMSA read · AD CS ESC1 · LAPS read · ESC8 probe.

```sh
# Audit a domain (low-priv creds are enough), export a BloodHound graph:
adhammer scan --url ldaps://dc.corp.local:636 --user 'CORP\svc' --password … --insecure --bloodhound out.zip

# ADIDNS + AD CS recon:
adhammer enum dns  --url ldaps://dc:636 --user 'CORP\svc' --password … --insecure
adhammer enum adcs --url ldaps://dc:636 --user 'CORP\svc' --password … --insecure   # + ESC8 web-enroll probe

# DCSync the krbtgt key, forge a golden ticket, pass-the-ticket to SYSTEM:
adhammer attack dcsync --host dc --domain CORP --user Administrator --password … --target krbtgt
adhammer attack pth    --host dc --realm CORP.LOCAL --krbtgt-aes256 <64-hex> --domain-sid S-1-5-21-… --spn cifs/dc.corp.local --command whoami
```

## Audit coverage

- **Privileged accounts** — AS-REP/Kerberoast exposure, unconstrained delegation, DCSync control
  paths (graph), sensitive-group membership, gMSA read ACL, SID history, RBCD, LAPS coverage,
  PASSWD_NOTREQD.
- **Trusts** — SID filtering, selective auth, cross-forest TGT delegation, RC4, transitivity.
- **Stale objects** — inactive users/computers, old passwords, EOL OS, duplicate SPNs, stale
  machine passwords.
- **Anomalies** — MachineAccountQuota, krbtgt age, RC4 Kerberos, reversible encryption,
  badSuccessor (dMSA), password policy, anonymous LDAP (dSHeuristics), Pre-Windows 2000 Compatible
  Access, Guest, GPP cpassword (MS14-025), and — from GptTmpl.inf — LM/NTLMv1, LDAP/SMB signing.
- **AD CS (15/16 ESC)** — passive: **ESC1, ESC2, ESC3, ESC4, ESC5, ESC9, ESC13, ESC14, ESC15/EKUwu
  (CVE-2024-49019)**; active: **ESC8** web-enrollment probe (`enum adcs`); registry over MS-RRP:
  **ESC6, ESC7, ESC10, ESC11, ESC16** (`enum esc`). Only ESC12 (hardware token) is out of scope.
- **ADIDNS** — zone/record enumeration with wildcard (mitm6/WPAD) detection (`enum dns`).

Every finding carries a MITRE ATT&CK technique (T1558.003 Kerberoasting, T1003.006 DCSync, T1649
cert abuse, T1484 policy/trust modification, …).

## Validated capabilities

Every audit finding is backed by a working technique, so a red team can confirm impact and a
defender can see exactly what the misconfiguration yields. All live-validated end-to-end against a
hardened **Server 2025** DC — and, to prove the Linux-native positioning, built on Kali and run
against the DC.

- **Recon / export** — `scan` (41 checks + graph as a low-priv user), `enum samr` / `enum lsa`,
  `enum net` (host/AD-port/SMB-signing sweep), `enum dns` (ADIDNS), `enum adcs` (CAs + ESC8),
  `enum esc` (ESC6/7/10/11/16 over MS-RRP), `enum posture` (LDAP signing/channel-binding + Spooler — relay/coercion enablers), `scan --bloodhound` (SharpHound-compatible zip).
- **Credential access** — **DCSync** single-object and full-domain (NT hashes + Kerberos keys incl.
  RFC 8009 AES-SHA2), **gMSA** and **LAPS** read over LDAPS, offline **secretsdump** (hand-rolled
  `regf` hive parser → bootkey → SAM/LSA/DCC2), **pass-the-hash**, **overpass-the-hash** (RC4→TGT).
- **Kerberos** — AS-REP + Kerberoast (RC4/AES), **RBCD** (S4U2Self→S4U2Proxy), **Shadow Credentials**
  PKINIT (incl. Server 2025 `paChecksum2` that breaks Rubeus/PKINITtools), **golden / silver
  tickets** with a from-scratch PAC (accepted by a patched 2025 KDC, KB5020805), **pass-the-ticket**
  over SMB.
- **Lateral / exec** — **SVCCTL** (psexec-style, LocalSystem, C$ output), **WinRM** (WS-Man + NTLM
  message encryption, no service-install event), **TSCH** (`atexec`), and **WMI** (`wmiexec` — DCOM
  activation → OXID resolve → `IWbemServices::ExecMethod Win32_Process.Create`, from a hand-built
  MS-DCOM/MS-WMIO stack, output over C$).
- **ADCS** — **ESC1** enrollment (spoofed-UPN SAN over MS-ICPR) → client-auth cert as the target,
  and **ESC6/7/10/11/16** decided from the CA/DC registry over **MS-RRP** (`enum esc`, the checks
  LDAP can't see — incl. ESC7 non-admin ManageCA/ManageCertificates from the CA `Security` SD).
- **Coercion / relay** — PetitPotam / PrinterBug, LLMNR/NBT-NS poisoning, SMB→LDAP NTLM relay
  (writes a Shadow Credential).

See **[VECTORS.md](VECTORS.md)** for the full closed / partial / open matrix and
**[ROADMAP.md](ROADMAP.md)** for what's next.

## Architecture

The protocol stack ships as **10 standalone, published crates** — this repo consumes them (the dogfooding proof, and the reusable "impacket for Rust"). All published under [`icedracon`](https://crates.io/users/icedracon) on crates.io, MIT-licensed, pure-Rust, no FFI.

| Published crate | Role |
|-----------------|------|
| [`windows-sddl`](https://crates.io/crates/windows-sddl) | no-FFI `SECURITY_DESCRIPTOR`/DACL/ACE parser (MS-DTYP) + `Sid`/`Guid` + AD extended-right GUIDs |
| [`ad-acl`](https://crates.io/crates/ad-acl) | AD ACE semantics — turn a security descriptor into concrete primitives (DCSync, Shadow Credentials, RBCD, WriteSPN, ReadGMSAPassword …) |
| [`ntlmssp`](https://crates.io/crates/ntlmssp) | NTLMSSP (NTLMv2, MIC, key-exch) + RC4 sign+seal for RPC packet privacy |
| [`smb2-client`](https://crates.io/crates/smb2-client) | async SMB2 client (negotiate → NTLMv2 SPNEGO → IPC$/named pipe; signing; SOCKS5 egress; **`TCP_NODELAY`** — 12× speedup on small-request paths) |
| [`ms-ndr`](https://crates.io/crates/ms-ndr) | NDR transfer syntax (MS-RPCE, LE): aligned primitives, conformant + varying arrays, unique-pointer referents, UTF-16 c-v strings |
| [`dcerpc`](https://crates.io/crates/dcerpc) | Sealed BIND · PDU reassembly · TCP + SMB pipe transports · EPM · SAMR · LSAT · DRSUAPI · SVCCTL · TSCH · EFSR · RPRN · ICPR · SRVSVC · FSRVP · DFSNM · Netlogon (Zerologon safe-detect) · DCOM/WMI (OXID → `Win32_Process.Create`) |
| [`dpapi-ng`](https://crates.io/crates/dpapi-ng) | DPAPI-NG (CNG group protection) + MS-GKDI — decrypt LAPS, gMSA, dMSA blobs offline |
| [`ms-dnsp`](https://crates.io/crates/ms-dnsp) | MS-DNSP `dnsRecord` blob parser/builder for AD-integrated DNS zones |
| [`preg`](https://crates.io/crates/preg) | Windows Group Policy `Registry.pol` (PReg) reader/writer |

Workspace crates (audit + orchestration): `core` (model + MITRE), `graph` (control-path,
reverse-Dijkstra to Tier-0, hops carry ready-to-copy `adhammer …` commands), `collector` (LDAP over
domain + Configuration NC), `checks` (the 41-rule engine), `kerberos` (roast · S4U/RBCD ·
Shadow-Cred PKINIT · golden/silver · pass-the-ticket), `sysvol` (GPP/GptTmpl, delegates to `preg`),
`report` (risk scoring → JSON/HTML), `ldap` (hand-rolled BER + NTLM SASL for the relay bridge),
`bloodhound` (SharpHound export), `secrets` (offline hive/SAM + WINREG-based `secretsdump`).

## Test

```sh
cargo test --workspace     # hermetic unit tests (no network)
```

Unit tests cover every parser, crypto primitive, and marshaler against spec vectors and round-trips
(NTOWFv2, RC4/RFC 6229, GPP AES key, NDR alignment, RPC PDUs, EPM towers, SMB2 signing, SAMR/LSAT,
PKINIT DH, PAC/DNS-record/LAPS parsing); ~50 more live in the extracted crates. Live-DC integration
tests in `cli/tests/integration.rs` are `#[ignore]`d — run against a lab with
`ADH_DC=… ADH_PASS=… cargo test --test integration -- --ignored --test-threads=1`.

`ldap3` links platform TLS (native-tls) so LDAPS works against legacy DCs whose handshake still uses
SHA-1 — which rustls refuses.

## Status & caveats

- All parsing, crypto, and marshaling are unit-tested; the audit and validated flows above are
  live-validated against **Server 2025 Standard** and **Server 2022** lab DCs. Every scenario in
  the bench matrix (Zerologon, ADCS, LDAP audit, LSAT, BadSuccessor, SAMR, DCSync, RBCD,
  Kerberoast, AS-REP, RRP secretsdump) confirmed working on the 2025 DC. 2022 additionally has 22
  flows run end-to-end — `scan`/`auto`, `enum` (`samr`/`lsa`/`net`/`dns`/`adcs`/`esc`/`sessions`),
  `roast` (RC4+AES) / `spray` / `dcsync --all`, `exec` (SVCCTL→SYSTEM) / `winrm` / `wmiexec`
  (DCOM) / `pth`, `golden` (KDC-accepted) / `silver` / `asktgt`, `secretsdump`, `abuse`
  (add-spn/set-password/add-member/write-rbcd), `coerce` (PrinterBug), and **ESC1** (low-priv →
  Administrator cert → PKINIT TGT). The 2016/2019/2012R2 matrix is on the roadmap.
- `attack capture`/`relay`/`poison` need a Linux attacker host (a Windows host holds TCP/445), which
  is the Kali-native positioning; `attack atexec` (TSCH) is a redundant RCE method that still
  faults `nca_s_fault_ndr` on modern targets — use `exec` (SVCCTL) or `winrm`.
- Default LDAP binds use LDAPS (`--insecure` for a lab self-signed cert; a bare username is
  auto-qualified to a UPN). Plaintext simple bind is refused by hardened DCs (Server 2025 requires
  LDAP sealing / LDAPS); SASL GSSAPI is an off-by-default cargo feature.
- **WMI exec** is live: `attack wmiexec` runs a full DCOM activation → OXID resolve →
  `IWbemServices::ExecMethod Win32_Process.Create` chain from the hand-built MS-DCOM/MS-WMIO stack,
  captures output over `C$`, and honors `-hashes` (PtH).
- ESC coverage: 7 of 16 ADCS ESC classes have active/enrollment paths (ESC1 via `attack esc1`,
  ESC4 via `attack esc4`, ESC6/10/11/16 via `enum esc` over MS-RRP, ESC8 web-enroll via `enum adcs`).
  ESC2/3/5/7/9/12/13/14/15 are audit-only in `scan` — active exploitation on the roadmap.

Authorized research / academic / authorized-engagement use only — see [SECURITY.md](SECURITY.md).
