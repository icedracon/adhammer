# ADhammer

Active Directory security assessment **and** offensive tradecraft in Rust — a PingCastle-class
auditor with an embedded, from-scratch protocol stack (the "impacket for Rust" that doesn't
otherwise exist). Built to run from Kali/Linux against Windows, as a single static binary.

ADhammer collects a domain over LDAP, builds a BloodHound-style control-path graph in process,
runs 33 checks across the four PingCastle categories, and scores the result. On top of the
passive audit it implements a working offensive stack — Kerberos roasting, password spray,
LDAP-object abuse, coercion, **RBCD**, and **Shadow Credentials (key-trust PKINIT)** — over a
native DCE/RPC · NTLM · SMB2 · Kerberos stack written from the wire up.

```
# Three commands cover everything:
#   scan                                            passive audit (checks + control-path graph + SYSVOL)
#   enum   {samr,lsa}                               read-only RPC enumeration
#   attack {roast,spray,abuse,coerce,rbcd}          active exploitation

adhammer scan  --url ldaps://dc.corp.local:636 --user CORP\\svc --password ... --insecure [--sysvol \\corp.local\SYSVOL]
adhammer attack roast  --url ldaps://... --user ... --password ... --insecure --kdc dc.corp.local
adhammer attack spray  --kdc dc.corp.local --realm CORP.LOCAL --users @users.txt --password 'Winter2025!'
adhammer attack rbcd   --account ... --account-password ... --realm CORP.LOCAL --kdc ... --impersonate Administrator --target-spn cifs/victim

# Shadow Credentials (two phases, same subcommand):
adhammer attack abuse --url ldaps://... --user ... --password ... --insecure --action add-keycred --target victim
adhammer attack abuse --action pkinit --target victim --realm CORP.LOCAL --kdc dc.corp.local   # → victim.ccache
```

`attack abuse` also does `add-spn` (targeted Kerberoast), `add-member`, `set-password`, and
`write-rbcd`. `attack coerce` is PetitPotam / MS-EFSR.

## Architecture

11 crates in one workspace, layered so the two audit differentiators — the self-rolled security
descriptor parser and the in-process control-path graph — sit on shared core types, and the
offensive tradecraft sits on the self-rolled RPC/Kerberos stack.

| Crate | Role |
|-------|------|
| `core` | Shared model: `Sid`/`Guid`, `AdObject`, `Snapshot`, `Finding`, MITRE table |
| `sddl` | ⭐ Self-rolled `SECURITY_DESCRIPTOR`/DACL/ACE parser (MS-DTYP) + RBCD SD builder + extended-right GUIDs |
| `graph` | ⭐ Control-path graph on `petgraph`; reverse-Dijkstra to Tier-0 |
| `collector` | LDAP collection (`ldap3`, rustls) over domain + Configuration NC; SD_FLAGS control; LDAP writes |
| `checks` | The 33-rule engine across all four categories |
| `kerberos` | AS-REP roast · Kerberoast (RC4+AES) · spray/enum · S4U/RBCD · **Shadow Credentials PKINIT** · ccache — on `picky-krb` |
| `sysvol` | GPP cpassword recovery (MS14-025) + GptTmpl.inf signing/NTLM/LM policy |
| `report` | Configurable risk scoring → JSON / HTML |
| `dcerpc` | NDR marshaling · RPC PDUs · **NTLMSSP sign+seal** · TCP/SMB transports · EPM · SAMR · LSAT · EFSR |
| `ntlm` | NTLMSSP (NTLMv2, MIC) + RC4 sign+seal (`SealState`) for RPC packet privacy |
| `smb` | Minimal SMB2 client (negotiate → NTLMv2 SPNEGO session → IPC$ → named-pipe RPC) |

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

## The embedded protocol stack

There is no impacket for Rust, so the RPC- and Kerberos-based capabilities are implemented from
the wire up and unit-tested against protocol specs:

```
NDR ─ PDU (bind/request/response, sign+seal) ─┬─ TCP transport ── EPM (ept_map)
                                               └─ SMB2 (+NTLMv2 SPNEGO) ── SAMR · LSAT · EFSR
Kerberos (picky-krb) ── AS-REQ/REP · TGS-REQ/REP · S4U2Self/Proxy (PA-FOR-USER) · PKINIT (DH + CMS)
```

## Offensive capabilities (live-validated)

Validated end-to-end against a hardened **Windows Server 2025** DC in a controlled lab:

- **Recon** — `scan` (33 checks + control-path graph, works as a low-priv user via the LDAP
  SD_FLAGS control), `enum samr` (full SAMR-over-SMB user enumeration), `enum lsa` (LSAT
  name↔SID).
- **Roasting** — AS-REP (no creds) and Kerberoast, emitting both RC4 (hashcat 13100/18200) and
  AES (19700) hashes; targeted Kerberoast via `abuse add-spn`.
- **RBCD** — full `write-rbcd` → S4U2Self → S4U2Proxy chain to an impersonation ticket, with a
  hand-rolled PA-FOR-USER checksum and PA-PAC-OPTIONS.
- **Shadow Credentials** — `add-keycred` writes a `msDS-KeyCredentialLink` KeyCredential, then
  `pkinit` performs key-trust PKINIT to obtain a TGT as the target and writes a reusable MIT
  ccache. Handles the Server 2025 `paChecksum2` PKAuthenticator requirement (SHA-256 over the
  KDC-REQ-BODY) that currently breaks Rubeus/PKINITtools.
- **Coercion** — PetitPotam / MS-EFSR (correctly reports patched DCs as not vulnerable).

## Build & test

```sh
cargo build --release      # target/release/adhammer(.exe)
cargo test --workspace     # 51 unit tests
```

Requires Rust 1.80+. `ldap3` uses rustls, so the tree builds as a static Linux/musl binary
(Kali → Windows is the point; PingCastle is Windows-only).

## Status & caveats

- All parsing, crypto, and marshaling are covered by unit tests (spec vectors + round-trips):
  NTOWFv2 (MS-NLMP §4.2.4.2), RC4 (RFC 6229), GPP AES key (MS14-025), NDR alignment/strings,
  RPC PDU shapes, EPM tower/port, SMB2 headers/signing, SAMR/LSAT marshaling, PKINIT DH group
  and reply-key derivation.
- The audit and offensive flows above are **live-validated** against a Server 2025 lab DC.
- **DCSync** (DRSUAPI) is in progress: the RPC sign+seal channel it needs is done and tested;
  the `DRSGetNCChanges` NDR and secret decryption are not yet implemented.
- Default LDAP binds require LDAPS (`--insecure` for a lab self-signed cert) or SASL GSSAPI
  (`--gssapi`, off-by-default cargo feature); plaintext simple bind is refused by hardened DCs.
  AD CS ESC5/6/7/8/10/11 are out of the current scope.

Authorized research / academic / authorized-engagement use only.
