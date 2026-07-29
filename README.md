# ADhammer

[![CI](https://github.com/icedracon/adhammer/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/adhammer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/icedracon/adhammer?sort=semver)](https://github.com/icedracon/adhammer/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Active Directory security assessment **and** offensive tradecraft in Rust — a PingCastle-class
auditor with an embedded, from-scratch protocol stack (the "impacket for Rust" that doesn't
otherwise exist). Built to run from Kali/Linux against Windows, as a single static binary.

> **Authorized use only.** ADhammer implements working offensive techniques (DCSync, golden/
> silver tickets, pass-the-ticket, NTLM relay, ADCS abuse, RCE). Use it only against systems you
> own or are explicitly authorized to test. See [SECURITY.md](SECURITY.md).

![ADhammer demo: DCSync → forge golden ticket → pass-the-ticket over SMB → SYSTEM, run from Kali Linux against a fully-patched Windows Server 2025 DC](docs/demo.gif)

*Above: a single Rust binary on Kali — DCSync the krbtgt key, forge a golden ticket, pass-the-ticket over SMB, and land code execution as `NT AUTHORITY\SYSTEM` on a fully-patched Server 2025 DC.*

ADhammer collects a domain over LDAP, builds a BloodHound-style control-path graph in process,
runs 33 checks across the four PingCastle categories, and scores the result. On top of the
passive audit it implements a working offensive stack — Kerberos roasting, password spray,
LDAP-object abuse, coercion, **RBCD**, **Shadow Credentials**, **DCSync**, **golden/silver
tickets**, and **pass-the-ticket** — over a native DCE/RPC · NTLM · SMB2 · Kerberos stack
written from the wire up.

## Why ADhammer

|                        | **ADhammer**                          | PingCastle                | impacket / Rubeus         |
|------------------------|---------------------------------------|---------------------------|---------------------------|
| Language               | Rust (single static binary)           | C# (.NET)                 | Python / C#               |
| Runs from              | Kali/Linux **and** Windows            | Windows only              | Linux (impacket) / Win    |
| Passive AD audit       | ✅ 33 checks + control-path graph      | ✅ (the reference)         | ❌                         |
| Offensive tradecraft   | ✅ roast/DCSync/tickets/relay/RCE      | ❌ (audit only)            | ✅ (offense only)          |
| Protocol stack         | from-scratch (no impacket dependency) | .NET libs                 | mature, batteries-included |
| Dependencies           | pure-Rust crates, no runtime          | .NET runtime              | Python runtime            |
| Live-validated on      | **Windows Server 2025** (patched)     | broad                     | broad                     |

The niche: **audit and offense in one Linux-native binary**, on a self-rolled stack — so the
security-descriptor parser and the RPC/NTLM/SMB layer are reusable Rust crates that don't
otherwise exist ([`windows-sddl`](https://crates.io/crates/windows-sddl),
[`ntlmssp`](https://crates.io/crates/ntlmssp),
[`smb2-client`](https://crates.io/crates/smb2-client),
[`dcerpc`](https://crates.io/crates/dcerpc)).

## Install

On Debian/Kali, install the build deps first (the LDAP layer links system TLS):

```sh
sudo apt-get install -y build-essential pkg-config libssl-dev
```

**From crates.io** (easiest):

```sh
cargo install adhammer
```

**Prebuilt binary** — grab `adhammer-vX.Y.Z-x86_64-linux` / `-windows.exe` from
[Releases](https://github.com/icedracon/adhammer/releases). **From source:**

```sh
git clone https://github.com/icedracon/adhammer && cd adhammer && cargo build --release
```

Requires Rust 1.80+ (`rustup`). Runs from Kali/Linux against Windows.

## Usage

```
# Interactive (prompts for domain/user, saves session, full guided attack menu):
adhammer                  # first run — enter creds, saved to ~/.config/adhammer/session.json
adhammer --old            # reuse saved session

# Power-user subcommands (unchanged):
#   scan                                            passive audit (checks + control-path graph + SYSVOL)
#   enum   {samr,lsa,net}                           read-only RPC / network enumeration
#   attack {roast,spray,abuse,coerce,rbcd,constrained,dcsync,exec,secretsdump,gmsa,esc1,
#           golden,silver,pth,asktgt,capture,poison,relay}

adhammer scan  --url ldaps://dc.corp.local:636 --user CORP\\svc --password ... --insecure [--sysvol \\corp.local\SYSVOL] [--bloodhound out.zip]
adhammer attack roast  --url ldaps://... --user ... --password ... --insecure --kdc dc.corp.local
adhammer attack spray  --kdc dc.corp.local --realm CORP.LOCAL --users @users.txt --password 'Winter2025!'
adhammer attack rbcd   --account ... --account-password ... --realm CORP.LOCAL --kdc ... --impersonate Administrator --target-spn cifs/victim

# Shadow Credentials (two phases, same subcommand):
adhammer attack abuse --url ldaps://... --user ... --password ... --insecure --action add-keycred --target victim
adhammer attack abuse --action pkinit --target victim --realm CORP.LOCAL --kdc dc.corp.local   # → victim.ccache

# DCSync a target (NT hash + Kerberos keys), then forge + use a golden ticket:
adhammer attack dcsync --host dc.corp.local --domain CORP --user Administrator --password ... --target krbtgt
adhammer attack golden --kdc dc.corp.local --realm CORP.LOCAL --krbtgt-aes256 <64-hex> --domain-sid S-1-5-21-a-b-c --verify-spn cifs/dc.corp.local
adhammer attack pth    --host dc.corp.local --realm CORP.LOCAL --krbtgt-aes256 <64-hex> --domain-sid S-1-5-21-a-b-c --spn cifs/dc.corp.local --command whoami
```

Or just run `adhammer` with no arguments for the **guided interactive menu**. It asks for
user → password (or NT hash) → domain → DC IP, saves the session, then walks you through all 21
actions with prompts. For golden/silver/pass-the-ticket it **auto-fetches** the krbtgt/service
AES256 key (via DCSync) and the domain SID (via LSAT) from your session — no pasting keys or SIDs.

![ADhammer first run: the setup wizard (user → password → domain → DC IP), then the 21-action menu, then DCSync krbtgt against the DC](docs/interactive.gif)

`attack abuse` also does `add-spn` (targeted Kerberoast), `add-member`, `set-password`, and
`write-rbcd`. `attack coerce` is PetitPotam / MS-EFSR.

## Architecture

The from-scratch protocol stack has been **extracted into standalone, published crates** — this
repo now consumes them, which is both the dogfooding proof and the reusable "impacket for Rust"
that didn't previously exist:

| Published crate | Role |
|-----------------|------|
| [`windows-sddl`](https://crates.io/crates/windows-sddl) | ⭐ no-FFI `SECURITY_DESCRIPTOR`/DACL/ACE parser (MS-DTYP) + `Sid`/`Guid` + AD extended-right GUIDs |
| [`ntlmssp`](https://crates.io/crates/ntlmssp) | NTLMSSP (NTLMv2, MIC, key-exch) + RC4 sign+seal for RPC packet privacy |
| [`smb2-client`](https://crates.io/crates/smb2-client) | async SMB2 client (negotiate → NTLMv2 SPNEGO → IPC$ → named pipe; signing; file read) |
| [`dcerpc`](https://crates.io/crates/dcerpc) | NDR · RPC PDUs · sign+seal · TCP/SMB transports · EPM · SAMR · LSAT · DRSUAPI · SVCCTL · EFSR · ICPR |

The audit- and orchestration-specific crates live in this workspace:

| Crate | Role |
|-------|------|
| `core` | Shared model: `AdObject`, `Snapshot`, `Finding`, MITRE table (re-exports `windows-sddl`'s `Sid`/`Guid`) |
| `graph` | ⭐ Control-path graph on `petgraph`; reverse-Dijkstra to Tier-0 |
| `collector` | LDAP collection (`ldap3`, native-tls) over domain + Configuration NC; SD_FLAGS control; LDAP writes |
| `checks` | The 33-rule engine across all four categories |
| `kerberos` | AS-REP roast · Kerberoast · spray/enum · S4U/RBCD · Shadow Credentials PKINIT · **golden/silver tickets · pass-the-ticket** · ccache |
| `sysvol` | GPP cpassword recovery (MS14-025) + GptTmpl.inf signing/NTLM/LM policy |
| `report` | Configurable risk scoring → JSON / HTML |
| `ldap` | Raw LDAP client (hand-rolled BER) with NTLM SASL GSS-SPNEGO bind — LDAP-389 auth + the NTLM-relay bridge |
| `bloodhound` | SharpHound-compatible BloodHound export (JSON + hand-rolled stored ZIP) |
| `secrets` | Offline registry-hive (`regf`) parser + bootkey + SAM NT-hash decryption (RC4/AES) |

## Audit coverage

**Privileged Accounts** — AS-REP/Kerberoast exposure, unconstrained delegation, DCSync control
paths (graph), sensitive-group membership, gMSA read ACL, SID history, RBCD, LAPS coverage,
PASSWD_NOTREQD.

**Trusts** — SID filtering, selective auth, TGT delegation across forest, RC4, transitivity.

**Stale Objects** — inactive users/computers, old passwords, EOL OS, duplicate SPNs, stale
machine passwords.

**Anomalies** — MachineAccountQuota, krbtgt age, RC4 Kerberos, reversible encryption,
badSuccessor (dMSA), **AD CS ESC1/2/3/4/9/13**, password policy, anonymous LDAP (dSHeuristics),
Pre-Windows 2000 Compatible Access, Guest, GPP cpassword, and — from SYSVOL GptTmpl.inf —
LM/NTLMv1, LDAP/SMB signing, NoLMHash, Netlogon sealing.

Every finding carries a MITRE ATT&CK technique (T1558.003 Kerberoasting, T1558.004 AS-REP,
T1003.006 DCSync, T1649 cert abuse, T1484 policy/trust modification, …).

## The protocol stack

There is no impacket for Rust, so the RPC- and Kerberos-based capabilities are implemented from
the wire up and unit-tested against protocol specs. The RPC/NTLM/SMB/SD layers now ship as the
standalone crates above; Kerberos remains in-workspace (on `picky-krb`):

```
NDR ─ PDU (bind/request/response, sign+seal) ─┬─ TCP transport ── EPM (ept_map)
                                               └─ SMB2 (+NTLMv2 SPNEGO) ── SAMR · LSAT · EFSR
Kerberos (picky-krb) ── AS-REQ/REP · TGS-REQ/REP · S4U2Self/Proxy (PA-FOR-USER) · PKINIT (DH + CMS)
```

## Offensive capabilities (live-validated)

Validated end-to-end against a hardened **Windows Server 2025** DC in a controlled lab — and, to
prove the Linux-native positioning, **built from source on Kali Linux and run against the DC**:
the full `DCSync → forge golden ticket → pass-the-ticket over SMB → command execution as
LocalSystem` chain succeeds from Kali against the patched DC.

- **Recon** — `scan` (33 checks + control-path graph, works as a low-priv user via the LDAP
  SD_FLAGS control), `enum samr` (full SAMR-over-SMB user enumeration), `enum lsa` (LSAT
  name↔SID). `scan --bloodhound out.zip` exports the domain as a SharpHound-compatible
  BloodHound zip (users/computers/groups/domains/ous/gpos/containers + ACE edges), so the
  in-process graph is explorable in the BloodHound UI.
- **Roasting** — AS-REP (no creds) and Kerberoast, emitting both RC4 (hashcat 13100/18200) and
  AES (19700) hashes; targeted Kerberoast via `abuse add-spn`.
- **RBCD** — full `write-rbcd` → S4U2Self → S4U2Proxy chain to an impersonation ticket, with a
  hand-rolled PA-FOR-USER checksum and PA-PAC-OPTIONS.
- **Shadow Credentials** — `add-keycred` writes a `msDS-KeyCredentialLink` KeyCredential, then
  `pkinit` performs key-trust PKINIT to obtain a TGT as the target and writes a reusable MIT
  ccache. Handles the Server 2025 `paChecksum2` PKAuthenticator requirement (SHA-256 over the
  KDC-REQ-BODY) that currently breaks Rubeus/PKINITtools.
- **Coercion** — PetitPotam / MS-EFSR (correctly reports patched DCs as not vulnerable).
- **DCSync** — `attack dcsync --target <sam>`: DRSBind → DRSCrackNames → DRSGetNCChanges
  (EXOP_REPL_OBJ) over the sealed channel, then session-key + per-RID-DES decryption of the
  NT hash → secretsdump format (`user:rid:lm:nt:::`). Verified against `krbtgt`/`Administrator`.
  `attack dcsync --all` enumerates every account via SAMR and replicates the whole domain (NTDS
  dump), reassembling multi-fragment replies so DC/computer accounts work too. Also extracts the
  **Kerberos keys** from `supplementalCredentials` (AES256/128 + RC4, incl. Server 2025's RFC 8009
  AES-SHA2 keys) — `user:etype:key` lines. The krbtgt AES256 key is the golden-ticket key.
- **Golden ticket** — `attack golden --krbtgt-aes256 <key> --domain-sid S-1-5-21-… [--user
  Administrator --rid 500 --groups 513,512,…]`: forge a TGT for any identity with a from-scratch
  PAC (KERB_VALIDATION_INFO NDR + SERVER/KDC HMAC-SHA1-96-AES256 signatures + PAC_REQUESTOR /
  PAC_ATTRIBUTES for KB5020805), sealed under the krbtgt key. `--verify-spn` proves KDC acceptance;
  `--out` writes an MIT ccache. Verified: a forged Domain-Admin TGT accepted by a fully-patched
  **Server 2025** KDC.
- **Silver ticket** — `attack silver --service-aes256 <key> --spn cifs/host --domain-sid …`: forge
  a service ticket (TGS) sealed + PAC-signed under a service account's key (from `dcsync` of the
  machine$/service account), presented directly to the service without the KDC.
- **Pass-the-ticket** — `attack pth --krbtgt-aes256|--service-aes256 <key> --domain-sid … --spn
  cifs/host [--command <cmd>]`: forge golden/silver → obtain the service ticket → authenticate to
  SMB with a Kerberos AP-REQ (GSS/SPNEGO) → run a command as the impersonated identity. Verified
  end-to-end on Server 2025: forged ticket → `whoami` = `nt authority\system` on the DC.
- **Exec** — `attack exec --command <cmd>`: psexec-style RCE over SVCCTL (MS-SCMR). Creates a
  service that runs the command as **LocalSystem** (detached so it survives SCM teardown),
  captures stdout/stderr back over `C$`, and deletes the service + temp file. Verified: `whoami`
  → `nt authority\system`.
- **Secretsdump (local)** — `attack secretsdump`: `reg save` the SYSTEM+SAM hives (as LocalSystem
  via exec), pull them over `C$`, then decrypt offline — hand-rolled `regf` hive parser → bootkey
  → SAM key → per-account NT hashes (RC4 and AES SAM revisions). Output cross-checked byte-for-byte
  against an independent implementation on live Server 2025 hives. Also dumps LSA secrets from the
  SECURITY hive ($MACHINE.ACC → NT hash, DPAPI_SYSTEM, service passwords) + cached DCC2 creds.
- **Pass-the-hash** — `--nt-hash <32-hex | LM:NT>` on `exec`/`secretsdump`/`enum samr`/`enum lsa`:
  authenticate with an NT hash instead of a password. Verified chain: `dcsync` Administrator →
  NT hash → `exec --nt-hash` → `nt authority\system`.
- **Overpass-the-hash** — `attack asktgt --user <u> --nt-hash <32-hex> --kdc dc`: turn an NT hash
  into a Kerberos **TGT** (ccache) via a from-scratch RC4-HMAC (etype 23) AS-exchange — the
  RC4 Kerberos key *is* the NT hash. For RC4-enabled DCs (Server ≤2022; also accepted by the
  2025 lab). Verified end-to-end: `recon` NT hash → TGT ccache.
- **gMSA read** — `attack gmsa --target svc$`: read `msDS-ManagedPassword` over LDAPS and derive
  the account's NT hash (for principals allowed to retrieve it). Verified: the recovered hash
  authenticates as the gMSA via pass-the-hash.
- **LAPS read** — `attack laps [--target HOST$]`: recover local-admin passwords over LDAPS —
  legacy `ms-Mcs-AdmPwd` and Windows LAPS `msLAPS-Password` (JSON); omit `--target` to sweep every
  computer you can read. Chain the cleartext into `attack exec`/`secretsdump` as the local admin.
  Verified vs Server 2025 (Windows LAPS).
- **AD CS ESC1** — `attack esc1 --ca <CA> --template <T> --upn Administrator@realm`: build a
  PKCS#10 CSR with the target UPN in the SAN, enroll it over sealed MS-ICPR (`\pipe\cert`), and
  save the issued client-auth cert + key. Verified: as low-priv `recon`, the CA issued a cert
  with `subject CN=Administrator` + `SAN UPN=Administrator@…` + Client-Auth EKU on an
  enrollee-supplies-subject template — the ESC1 escalation, end to end.

See **[VECTORS.md](VECTORS.md)** for the full closed / partial / open vector matrix, and
**[ROADMAP.md](ROADMAP.md)** for the prioritized post-1.0 build plan (what's next, why, and effort).

## Test

```sh
cargo test --workspace     # hermetic unit tests (no network)
```

The workspace's 56 unit tests cover the audit/graph/kerberos/secrets layers; the protocol-stack
tests (~50 more) live in the extracted crates (`windows-sddl`/`ntlmssp`/`smb2-client`/`dcerpc`).
Live-DC integration tests in `cli/tests/integration.rs` are `#[ignore]`d — run them against a lab
with `ADH_DC=… ADH_PASS=… cargo test --test integration -- --ignored`.

Runs from Kali/Linux against Windows (Kali → Windows is the point; PingCastle is Windows-only).
`ldap3` links platform TLS (native-tls) so LDAPS works against legacy DCs whose handshake still
uses SHA-1 — which rustls refuses.

## Status & caveats

- All parsing, crypto, and marshaling are covered by unit tests (spec vectors + round-trips):
  NTOWFv2 (MS-NLMP §4.2.4.2), RC4 (RFC 6229), GPP AES key (MS14-025), NDR alignment/strings,
  RPC PDU shapes, EPM tower/port, SMB2 headers/signing, SAMR/LSAT marshaling, PKINIT DH group
  and reply-key derivation.
- The audit and offensive flows above are **live-validated** against a Server 2025 lab DC.
- Default LDAP binds require LDAPS (`--insecure` for a lab self-signed cert) or SASL GSSAPI
  (`--gssapi`, off-by-default cargo feature); plaintext simple bind is refused by hardened DCs.
  AD CS ESC5/6/7/8/10/11 are out of the current scope — see [VECTORS.md](VECTORS.md).

Authorized research / academic / authorized-engagement use only.
