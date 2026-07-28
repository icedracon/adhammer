# Changelog

All notable changes to ADhammer are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); this project uses SemVer.

## [1.0.0] — 2026-07-28

First stable release. A single Linux-native Rust binary that both **audits** Active Directory
and **exploits** it, on a from-scratch DCE/RPC · NTLM · SMB2 · Kerberos stack. Every offensive
capability below is live-validated end-to-end against a fully-patched **Windows Server 2025** DC.

### Audit
- 33 checks across the four PingCastle categories, with per-finding MITRE ATT&CK mapping.
- In-process BloodHound-style control-path graph (reverse-Dijkstra to Tier-0); works as a
  low-privileged user via the LDAP `SD_FLAGS` control.
- SharpHound-compatible BloodHound export (`scan --bloodhound`).
- SYSVOL / GPP cpassword (MS14-025) and GptTmpl.inf policy analysis.

### Offense (live-validated vs Server 2025)
- **Roasting** — AS-REP and Kerberoast (RC4 13100 + AES 19700); requests RC4 **and** AES so
  AES-only services still yield a ticket.
- **Password spray** + user/AS-REP-roastable enumeration.
- **LDAP-object abuse** — add-spn, add-member, set-password, write-rbcd, Shadow Credentials
  (`msDS-KeyCredentialLink`).
- **RBCD** and **constrained delegation** — full S4U2Self → S4U2Proxy chains.
- **Shadow Credentials PKINIT** — key-trust TGT, incl. the Server 2025 `paChecksum2`
  (SHA-256 over the KDC-REQ-BODY) requirement that breaks Rubeus/PKINITtools there.
- **Coercion** — PetitPotam / MS-EFSR and PrinterBug / MS-RPRN.
- **DCSync** — single-object and full-domain, over sealed DRSUAPI; extracts NT hashes **and**
  Kerberos keys (AES256/128, RC4, and Server 2025's RFC 8009 AES-SHA2 etypes 19/20).
- **Golden / silver tickets** — from-scratch PAC (`KERB_VALIDATION_INFO` NDR + SERVER/KDC
  signatures + `PAC_REQUESTOR`/`PAC_ATTRIBUTES` for KB5020805). Forged Domain-Admin TGT accepted
  by a fully-patched 2025 KDC.
- **Pass-the-ticket** — Kerberos AP-REQ over SMB2 (GSS/SPNEGO); run commands as the impersonated
  identity. Verified: forged ticket → `NT AUTHORITY\SYSTEM` on the DC, from Kali.
- **Pass-the-hash** — `--nt-hash` on exec/secretsdump/enum.
- **Overpass-the-hash** — RC4-HMAC AS-exchange turns an NT hash into a Kerberos TGT.
- **RC4 golden/silver** — `--rc4` (KERB_CHECKSUM_HMAC_MD5 PAC signatures) for RC4-enabled
  (Server ≤2022) DCs.
- **Exec / secretsdump** — SVCCTL LocalSystem RCE with `C$` output capture; offline SAM/LSA/DCC2
  from reg-saved hives.
- **gMSA read**, **AD CS ESC1**, **NTLM relay** (SMB → LDAP shadow-cred), **capture/poison**
  (NTLMv2 → hashcat, LLMNR/NBT-NS).

### Protocol stack — published as standalone crates
Extracted from this repo (the "impacket for Rust" that didn't exist):
[`windows-sddl`](https://crates.io/crates/windows-sddl),
[`ntlmssp`](https://crates.io/crates/ntlmssp),
[`smb2-client`](https://crates.io/crates/smb2-client),
[`dcerpc`](https://crates.io/crates/dcerpc). ADhammer consumes them.

### Interface
- Guided interactive TUI (`adhammer`): user → password/NT-hash → domain → DC, then all 21
  actions; golden/silver/pth auto-fetch the key (DCSync) and domain SID (LSAT) from the session.
- Power-user subcommands: `scan`, `enum {samr,lsa,net}`,
  `attack {roast,spray,abuse,coerce,rbcd,constrained,dcsync,exec,secretsdump,gmsa,esc1,golden,silver,pth,asktgt,capture,poison,relay}`.

### Quality
- ~110 tests across the workspace + extracted crates (spec vectors + round-trips), a live-DC
  integration harness, and GitHub Actions CI. Zero clippy/build warnings. Parser fuzzing.

### Known limitations
- Live validation is against Server 2025 only; the 2016/2019/2022 matrix is not yet recorded.
- RC4 golden→TGS completion needs an RC4-service DC (≤2022); on 2025 the forged RC4 TGT is
  accepted but the service ticket is refused (KDC policy).
- BloodHound export is schema-validated, not yet UI-confirmed.
- Open vectors (roadmap): noPac, Zerologon, ADCS ESC5–11, DCShadow, LAPS, trust-key dumping —
  see [VECTORS.md](VECTORS.md).

Authorized testing / research / education only — see [SECURITY.md](SECURITY.md).
