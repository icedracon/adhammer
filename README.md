# ADhammer

Passive Active Directory security assessment in Rust — a PingCastle-class auditor with an
embedded, from-scratch protocol stack (the "impacket for Rust" that doesn't otherwise exist).

ADhammer collects a domain over LDAP, builds a BloodHound-style control-path graph in
process, runs 33 checks across the four PingCastle categories, and scores the result. It
additionally implements Kerberos roasting, GPP/GptTmpl SYSVOL analysis, and a native
DCE/RPC · NTLM · SMB2 · SAMR stack for enumeration LDAP cannot reproduce.

```
adhammer scan  --url ldaps://dc.corp.local:636 --user CORP\\svc --password ... [--sysvol \\corp.local\SYSVOL]
adhammer attack roast --url ldaps://dc.corp.local:636 --user CORP\\svc --password ... --insecure --kdc dc.corp.local

# Three commands cover everything:
#   scan                  passive audit (checks + control-path graph + SYSVOL)
#   enum   {samr,lsa}     read-only RPC enumeration
#   attack {roast,spray,abuse,coerce,rbcd}   active exploitation
```

## Architecture

11 crates in one workspace, layered so the two differentiators — the self-rolled security
descriptor parser and the in-process control-path graph — sit on shared core types.

| Crate | Role |
|-------|------|
| `core` | Shared model: `Sid`/`Guid`, `AdObject`, `Snapshot`, `Finding`, MITRE table |
| `sddl` | ⭐ Self-rolled `SECURITY_DESCRIPTOR`/DACL/ACE parser (MS-DTYP) + extended-right GUIDs |
| `graph` | ⭐ Control-path graph on `petgraph`; reverse-Dijkstra to Tier-0 |
| `collector` | LDAP collection (`ldap3`) over the domain + Configuration NC |
| `checks` | The 33-rule engine across all four categories |
| `kerberos` | AS-REP roast (no creds) + Kerberoast (TGT → TGS), on `picky-krb` |
| `sysvol` | GPP cpassword recovery (MS14-025) + GptTmpl.inf signing/NTLM/LM policy |
| `report` | Configurable risk scoring → JSON / HTML |
| `dcerpc` | NDR marshaling · RPC PDUs · TCP/SMB transports · EPM · SAMR |
| `ntlm` | NTLMSSP (NTLMv2, key exchange, MIC) |
| `smb` | Minimal SMB2 client (negotiate → NTLM session → IPC$ → named-pipe RPC) |

## Coverage

**Privileged Accounts** — AS-REP/Kerberoast exposure, unconstrained delegation, DCSync
control paths (graph), sensitive-group membership, gMSA read ACL, SID history, RBCD, LAPS
coverage, PASSWD_NOTREQD.

**Trusts** — SID filtering, selective auth, TGT delegation across forest, RC4, transitivity.

**Stale Objects** — inactive users/computers, old passwords, EOL OS, duplicate SPNs, stale
machine passwords.

**Anomalies** — MachineAccountQuota, krbtgt age, RC4 Kerberos, reversible encryption,
badSuccessor (dMSA), **AD CS ESC1/2/3/4/9/13**, password policy, anonymous LDAP
(dSHeuristics), Pre-Windows 2000 Compatible Access, Guest, GPP cpassword, and — from
SYSVOL GptTmpl.inf — LM/NTLMv1, LDAP/SMB signing, NoLMHash, Netlogon sealing.

Every finding carries a MITRE ATT&CK technique (T1558.003 Kerberoasting, T1558.004 AS-REP,
T1003.006 DCSync, T1649 cert abuse, T1484 policy/trust modification, …).

## The embedded protocol stack

There is no impacket for Rust, so the RPC-based capabilities are implemented from the wire
up and unit-tested against protocol specs:

```
NDR (marshaling) ─ PDU (bind/request/response) ─┬─ TCP transport ── EPM (ept_map)
                                                 └─ SMB2 (+NTLMv2) ── SAMR
                                                     connect → enum-domains → lookup → open → enum-users
```

Verified offline with spec test vectors and encode/decode round-trips:
NTOWFv2 (MS-NLMP §4.2.4.2), GPP AES key (MS14-025), NDR alignment/strings, RPC PDU shapes,
EPM tower + port, SMB2 headers/signing, SAMR SID + enumeration marshaling.

## Build & test

```sh
cargo build --release      # target/release/adhammer(.exe)
cargo test --workspace     # 37 unit tests
```

Requires Rust 1.80+. Builds clean with zero warnings.

## Status & caveats

- All parsing, crypto, and marshaling are covered by unit tests (spec vectors + round-trips).
- **Network flows** (LDAP bind, Kerberos AS/TGS, SMB2/RPC to a live KDC/DC) are constructed
  to spec but have **not** been validated against a production domain from this tree; run
  live validation in a controlled lab.
- SMB uses dialect 2.1.0 with raw NTLMSSP in the session-setup buffer; AD CS ESC5/6/7/8/10/11
  and DRSUAPI/LSAT are out of the current scope.

Authorized research / academic use only.
