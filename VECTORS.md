# ADhammer — Vector Coverage & Roadmap

Status key:

| Symbol | Meaning |
|--------|---------|
| ✅ | Closed — implemented and live-validated (or unit-tested where passive-only) |
| 🔶 | Partial — detection or trigger exists; exploit chain incomplete |
| ❌ | Open — not implemented |
| 🚫 | Out of scope — requires different tooling or active relay not in passive audit |

Last updated: 2026-07-29 · v1.0.0

---

## Quick summary

| Area | Closed | Partial | Open |
|------|--------|---------|------|
| Audit checks (41 rules) | 39 | 2 | 0 |
| AD CS ESC (15/16) | ESC1/2/3/4/5/9/13/14/15 passive + ESC8 active + ESC6/7/10/11/16 via MS-RRP (`enum esc`) | — | ESC12 (hardware token, out of scope) |
| Offensive CLI | 21 modes (roast·spray·abuse·coerce·rbcd·constrained·dcsync·exec·secretsdump·gmsa·esc1·golden·silver·pth·asktgt·capture·poison·relay…) | 2 chains | see [ROADMAP.md](ROADMAP.md) |
| Protocol stack | NDR·RPC·NTLM·SMB2·Kerberos (AS/TGS/S4U/PKINIT + from-scratch PAC + RC4-HMAC) | DRSUAPI single-object | SVCCTL✅·TSCH·RRPM·NETLOGON… |

**Post-1.0 backlog is planned as milestones — see [ROADMAP.md](ROADMAP.md)** (v1.1 lateral+LAPS,
v1.2 ADCS ESC8/11, v1.3 legacy matrix + noPac). This file tracks per-vector status; ROADMAP tracks
the release plan.

See [Open vectors](#open-vectors-not-yet-closed) for the full backlog.

---

## Audit — Privileged Accounts

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| P-AsrepRoast | AS-REP roastable (DONT_REQ_PREAUTH) | ✅ | `checks/privileged.rs` |
| P-KerberoastAdmin | Privileged + SPN | ✅ | adminCount=1 filter |
| P-UnconstrainedDelegation | TRUSTED_FOR_DELEGATION on non-DC | ✅ | Excludes primaryGroup 516 |
| P-DcsyncPath | Control path to Tier-0 (cost ≤1) | ✅ | Graph-backed |
| P-ShadowCred | AddKeyCredential write on Tier-0 | ✅ | Graph-backed (`direct_edges_to_tier0`) |
| P-SensitiveGroups | Operators / Schema Admins membership | ✅ | `privileged_extra.rs` |
| P-GmsaBroadRead | gMSA password readable by broad principals | ✅ | LDAP ACL parse |
| P-SidHistory | sIDHistory with privileged SID | ✅ | |
| P-Rbcd | msDS-AllowedToActOnBehalfOfOtherIdentity set | ✅ | Config detection only |
| P-Laps | Computers without LAPS | ✅ | ms-Mcs-AdmPwd absent |
| P-PasswdNotReqd | PASSWD_NOTREQD accounts | ✅ | |
| P-PrimaryGroupPriv | Privileged via primaryGroupID (hidden membership) | ✅ | Stealth Domain-Admin persistence; live-validated |
| P-DormantPrivileged | adminCount=1 accounts inactive > 90d | ✅ | |
| P-DefaultAdminActive | Built-in Administrator (RID 500) in active use | ✅ | Break-glass hygiene; live-validated |

---

## Audit — Stale Objects

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| S-Inactive | Inactive users/computers | ✅ | lastLogon threshold |
| S-UnsupportedOs | EOL operatingSystem | ✅ | |
| S-PasswordNeverChanged | pwdLastSet never set | ✅ | |
| S-StaleComputers | Stale computer accounts | ✅ | |
| S-MachinePasswordAge | Old machine password | ✅ | |
| S-DuplicateSpn | Duplicate servicePrincipalName | ✅ | |
| S-DisabledInPrivGroup | Disabled accounts still stamped adminCount=1 | ✅ | AdminSDHolder residue; live-validated (krbtgt) |
| S-NeverLoggedOn | Enabled accounts created long ago, never logged on | ✅ | |

---

## Audit — Trusts

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| T-SidFiltering | SID filtering disabled on trust | ✅ | |
| T-SelectiveAuth | Selective authentication off | ✅ | |
| T-TgtDelegation | TGT delegation across trust | ✅ | |
| T-Rc4Trust | RC4 inter-realm trust keys | ✅ | |
| T-TransitiveExternal | Transitive external trust | ✅ | |

---

## Audit — Anomalies

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| A-MachineAccountQuota | ms-DS-MachineAccountQuota > 0 | ✅ | |
| A-KrbtgtAge | krbtgt password age | ✅ | |
| A-ReversibleEncryption | ENCRYPTED_TEXT_PWD_ALLOWED | ✅ | |
| A-Rc4Kerberos | RC4 on service accounts | ✅ | |
| A-PrivPwdNeverExpires | Privileged accounts with non-expiring passwords | ✅ | live-validated (svc_sql) |
| A-DesOnly | Accounts restricted to DES Kerberos keys | ✅ | |
| A-FunctionalLevel | Domain functional level < 2016 | ✅ | msDS-Behavior-Version |
| A-BadSuccessor | dMSA objects present | 🔶 | **Partial** — flags presence only; does not yet walk OU ACLs for CreateChild/Write delegation |
| A-WeakPasswordPolicy | Domain password policy | ✅ | minPwdLength / complexity |
| A-DsHeuristics | Anonymous LDAP bind allowed | ✅ | |
| A-PreWin2000 | Pre-Windows 2000 Compatible Access | ✅ | |
| A-ProtectedUsers | Protected Users group unused | ✅ | |
| A-Guest | Guest account enabled | ✅ | |
| A-GppCpassword | GPP cpassword in SYSVOL | ✅ | Requires `--sysvol` on scan |
| A-GptTmpl | LM/NTLM/signing from GptTmpl.inf | ✅ | Requires `--sysvol` |

---

## Audit — AD Certificate Services (ESC)

Passive LDAP-only detection in `checks/adcs.rs`. Templates must be **published** on a CA.

| ESC | Description | Status | Blocker |
|-----|-------------|--------|---------|
| ESC1 | Enrollee-supplies-subject + auth EKU, low-priv enroll | ✅ | |
| ESC2 | Any-Purpose / SubCA, low-priv enroll | ✅ | |
| ESC3 | Enrollment Agent template, low-priv enroll | ✅ | |
| ESC4 | Template ACL writable by low-priv | ✅ | |
| ESC5 | Vulnerable PKI object ACL (CA server) | ✅ | Broad-principal Write/Owner over `pKIEnrollmentService`/`certificationAuthority` objects (reuses the template ACL walk) |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | ✅ | `enum esc` reads the policy-module `EditFlags` over MS-RRP (live-validated, Server 2022) |
| ESC7 | Vulnerable CA ACL (ManageCa / ManageCertificates) | ✅ | `enum esc` parses the CA `Security` SD over MS-RRP; flags non-Tier-0 ManageCA/ManageCertificates (live-validated, Server 2022) |
| ESC8 | Web Enrollment HTTP relay | 🔶 | **Detection done** (`enum adcs`): probes each CA host's `http://…/certsrv` for a cleartext NTLM 401 (relayable). Relay *exploit* still open (see ESC8 in the relay backlog) |
| ESC9 | CT_FLAG_NO_SECURITY_EXTENSION + auth EKU | ✅ | |
| ESC10 | Weak certificate mapping on DC | ✅ | `enum esc` reads the DC `Kdc\StrongCertificateBindingEnforcement` over MS-RRP (live-validated, Server 2022) |
| ESC11 | ICPR RPC relay | 🔶 | **Detection done** (`enum esc`): CA `InterfaceFlags` lacks `IF_ENFORCEENCRYPTICERTREQUEST` ⇒ relayable. Active relay to `\cert` pipe still open |
| ESC13 | Issuance policy → privileged group link | ✅ | |
| ESC14 | Weak explicit cert mapping (`altSecurityIdentities`) | ✅ | Flags Subject-only / Issuer+Subject / RFC822 X509 mappings; live-validated |
| ESC15 / EKUwu | Schema v1 + application-policy injection (CVE-2024-49019) | ✅ | Any enrollable v1 template; live-validated on the lab |
| ESC16 | Security extension globally disabled on CA | ✅ | `enum esc` reads the policy-module `DisableExtensionList` over MS-RRP (live-validated, Server 2022) |

**Offensive AD CS:** ✅ **ESC1** enrollment end-to-end (`attack esc1`: PKCS#10 + spoofed-UPN SAN over
MS-ICPR → client-auth cert → PKINIT TGT; live-validated low-priv → Administrator on Server 2022).
Detection now covers ESC1/2/3/4/5/6/7/8/9/10/11/13/14/15/16 (**15/16**; only ESC12 hardware-token
is out of scope).

---

## Offensive — Closed vectors

| Vector | CLI | Status | Crate / path |
|--------|-----|--------|--------------|
| Passive domain audit | `scan` / interactive | ✅ | collector → graph → checks → report |
| Kerberoast (RC4 + AES) | `attack roast` | ✅ | kerberos |
| AS-REP roast | `attack roast` + `--kdc` | ✅ | kerberos |
| Targeted Kerberoast | `attack abuse --action add-spn` | ✅ | collector LDAP write |
| Password spray | `attack spray` | ✅ | kerberos |
| SAMR user enum | `enum samr` | ✅ | dcerpc/samr over SMB |
| LSAT name→SID | `enum lsa` | ✅ | dcerpc/lsat |
| Network sweep + deep checks | `enum net [--deep]` | ✅ | cli/main.rs |
| LDAP add-spn / add-member / set-password | `attack abuse` | ✅ | collector |
| Shadow Credentials phase 1 | `attack abuse --action add-keycred` | ✅ | kerberos/shadowcred + LDAP |
| Shadow Credentials phase 2 (PKINIT) | `attack abuse --action pkinit` | ✅ | kerberos/pkinit (Server 2025 paChecksum2) |
| RBCD write + S4U chain | `attack abuse write-rbcd` + `attack rbcd` | ✅ | sddl + kerberos/tgs |
| PetitPotam / MS-EFSR | `attack coerce --pipe lsarpc\|efsrpc` | ✅ | dcerpc/efsr |
| PrinterBug / MS-RPRN | `attack coerce --pipe spoolss` | ✅ | dcerpc/rprn |
| DCSync (single object) | `attack dcsync --target` | ✅ | dcerpc/drsuapi sealed |
| NTLM capture listener | `attack capture` | ✅ | smb/server |
| LLMNR/NBT-NS poison | `attack poison` | ✅ | cli/poison |
| NTLM relay → LDAP keycred | `attack relay` | ✅ | smb/server + ldap |
| GPP cpassword decrypt | `scan --sysvol` | ✅ | sysvol/gpp |

---

## Offensive — Partial vectors

| Vector | Status | What's missing |
|--------|--------|----------------|
| **Coerce → capture chain** | 🔶 | Coerce and capture are separate; no single command wires listener + trigger + hash output |
| **Coerce → relay → pkinit** | 🔶 | Three manual steps; no orchestrated `attack chain shadowcred` |
| **DCSync** | 🔶 | EXOP_REPL_OBJ per target only — no full domain replication / NTDS.dit |
| **Kerberoast without creds** | 🔶 | AS-REP needs no creds; Kerberoast needs authenticated TGT |
| **badSuccessor exploit** | 🔶 | Audit flags dMSA presence; no OU ACL graph or dMSA takeover primitive |
| **Net deep checks** | 🔶 | FTP/SMTP/Redis/VNC/WinRM/RPC surface only — no auto-exploit |
| **EPM RPC surface** | 🔶 | `enum net --deep` reports DRSUAPI/SVCCTL/TSCH/EFSR/RPRN registered — no follow-up exploits except coerce/dcsync |

---

## Open vectors — not yet closed

### Kerberos & credentials

| Vector | Priority | Notes |
|--------|----------|-------|
| Pass-the-ticket (Kerberos AP-REQ over SMB) | ✅ | `attack pth` — forge golden/silver → service ticket → SMB AP-REQ → SYSTEM RCE (live Server 2025) |
| Pass-the-hash (SMB) | ✅ | `--nt-hash` on exec/secretsdump/samr/lsa (live-validated) |
| Overpass-the-hash (RC4→TGT) | ✅ | `attack asktgt --nt-hash` — from-scratch RC4-HMAC AS-exchange; NT hash → TGT (live-validated) |
| Constrained delegation abuse | ✅ | `attack constrained` (S4U2Self/S4U2Proxy) |
| Unconstrained delegation TGT capture | Medium | No `monitor` / `delegate` mode on coerced auth |
| Golden ticket forge | ✅ | `attack golden` — from-scratch PAC (KERB_VALIDATION_INFO + SERVER/KDC sigs + PAC_REQUESTOR/ATTRIBUTES); forged DA TGT **accepted by patched Server 2025 KDC (KB5020805)** |
| Silver ticket forge | ✅ | `attack silver` — service-key TGS; live SYSTEM RCE via `attack pth` |
| RC4 golden/silver forge | ✅ | `--rc4` on golden/silver/pth — KERB_CHECKSUM_HMAC_MD5 PAC sigs; forge byte-verified (offline round-trip); live golden→TGS needs an RC4-service DC (≤2022) |
| DCSync Kerberos keys | ✅ | `attack dcsync` dumps AES256/128 + RC4 from supplementalCredentials (incl. RFC 8009 AES-SHA2) |
| noPac (CVE-2021-42278/87) | Medium | MAQ check exists; no samAccountName rename chain |
| AS-REP roast AES-only accounts | Low | Bails on non-RC4 AS-REP (`kerberos/lib.rs`) |

### LDAP / AD object abuse

| Vector | Priority | Notes |
|--------|----------|-------|
| DCSync via pure LDAP (WS2025 hybrid) | Medium | DRSUAPI path done; LDAP-only replication path not implemented |
| GMSA password read | ✅ | `attack gmsa` reads msDS-ManagedPassword → NT hash (live-validated) |
| LAPS password read | ✅ | `attack laps` reads `ms-Mcs-AdmPwd` (legacy) + `msLAPS-Password` (Windows LAPS JSON) over LDAPS — one host or sweep-all; live-validated. Encrypted `msLAPS-EncryptedPassword` (DPAPI-NG) surfaced but not decrypted |
| AdminSDHolder / ACL backdoor write | Medium | Graph detects paths; no `attack dacl` helper |
| ADIDNS enumeration (adidnsdump-style) | ✅ | `enum dns` — reads all zones/records from DomainDnsZones/ForestDnsZones over LDAP, parses `dnsRecord` (A/AAAA/CNAME/NS/SOA/SRV/MX/TXT/PTR), flags wildcard nodes; live-validated |
| ADIDNS record write / mitm6 spoofing | ❌ | enumeration + wildcard detection done; no record-write primitive yet |
| Group Policy abuse (GPO edit) | Low | SYSVOL read only |

### Relay & coercion

| Vector | Priority | Notes |
|--------|----------|-------|
| ESC8 — relay to Web Enrollment | High | Needs HTTP client + cert request template |
| ESC11 — relay to ICPR `\cert` | High | Cert RPC not in dcerpc crate |
| SMB → LDAPS relay (EPA/channel binding bypass) | Medium | Relay targets LDAP :389 only |
| IPv6 DNS takeover | Low | Poison is IPv4 LLMNR/NBT-NS only |
| DCOM / WMI coercion | Low | No DCOM stack |

### RPC / remote execution (detected via EPM, not exploited)

| Vector | Priority | MS-RPC | Status |
|--------|----------|--------|--------|
| Remote service creation | High | SVCCTL | ✅ `attack exec` (SYSTEM + C$ output) |
| Scheduled task | High | TSCH | ❌ |
| Remote Registry | Medium | RRPM | ❌ |
| Print spooler (beyond PrinterBug) | Low | RPRN | 🔶 coerce only |
| Workstation / user enum | Low | WKST / SAMR | 🔶 SAMR users only |

### AD CS offensive

| Vector | Priority | Notes |
|--------|----------|-------|
| Cert enrollment (ESC1/2/3) | High | Certipy-class |
| ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 | Medium | CA flag + request |
| ESC7 ManageCertificates takeover | Medium | |
| ESC10 certificate mapping bypass | Medium | DC-side |

### Protocol stack gaps

| Component | Status | Notes |
|-----------|--------|-------|
| NDR encode/decode | ✅ | `dcerpc/ndr.rs` |
| RPC bind / sign+seal (NTLM) | ✅ | `dcerpc/pdu.rs`, `ntlm` |
| SMB2 client | ✅ | Minimal — IPC$ + pipes |
| SMB2 server (capture/relay) | ✅ | `smb/server.rs` |
| EPM port mapping | ✅ | TCP |
| SAMR / LSAT / EFSR / DRSUAPI / RPRN | ✅ | |
| Kerberos AS/TGS/S4U/PKINIT | ✅ | picky-krb |
| LDAP (ldap3 TLS + custom NTLM SASL) | ✅ | collector + ldap crate |
| GSSAPI / Kerberos LDAP bind | 🔶 | `--gssapi` feature off by default |
| LDAP channel binding | ❌ | Relay mitigations not implemented |
| SMB3 encryption | ❌ | Signing probe only |
| SCHRPC / SVCCTL / TSCH / RRPM | ❌ | |
| NETLOGON / Zerologon | ❌ | |
| WINRM / WS-MAN | ✅ | `attack winrm` — NTLM + MS-NLMP message encryption over 5985, full shell lifecycle, PtH; live-validated |
| Full DRS replication (GetNCChanges bulk) | ❌ | Single-object EXOP only |

### Graph / analysis gaps

| Feature | Status | Notes |
|---------|--------|-------|
| Deny-ACE aware pathing | ❌ | Allow-only model (`graph/lib.rs` comment) |
| Cross-domain / forest trust paths | 🔶 | Trust *checks* exist; graph is single-domain |
| Tier model customization | ❌ | Hardcoded Tier-0 RIDs |
| BloodHound export (JSON) | ✅ | `scan --bloodhound out.zip` (SharpHound v5) |
| Historical diff (scan over time) | ❌ | |

### UX / product

| Item | Status | Notes |
|------|--------|-------|
| Interactive mode | ✅ | `adhammer` / `adhammer --old` |
| Power-user subcommands | ✅ | `scan`, `enum`, `attack` preserved |
| Release static binary (musl) | ❌ | No CI release |
| DC integration test in CI | ❌ | Unit tests only |
| HTML report polish | 🔶 | Basic template in `report/` |
| MITRE mapping completeness | 🔶 | Per-finding tags; no ATT&CK navigator export |

---

## Close order (roadmap)

Pass-the-ticket, constrained delegation, GMSA read, SVCCTL exec, cert enrollment (ESC1) and
full-domain DCSync from the original list are **shipped in v1.0.0**. The remaining backlog is
sequenced into releases in **[ROADMAP.md](ROADMAP.md)**:

1. **v1.1** — LAPS read · WinRM exec · WMI exec · session hygiene (provable on the 2025 lab).
2. **v1.2** — ESC8/ESC11 relay→CA→PKINIT · ESC4 · ExtraSids-golden · LDAPS object-create plumbing.
3. **v1.3** — legacy-DC matrix (2008 R2 →) · noPac · unconstrained-deleg TGT capture · cross-forest.
4. **v1.4+** — mitm6/relay→SMB · GPO write · MSSQL · DCShadow · golden cert · remaining ESC.

---

## References

- [README.md](README.md) — build, architecture, live-validated flows
- [lab/README.md](lab/README.md) — WS2025 lab setup
- SpecterOps AD CS ESC definitions
- PingCastle rule categories (parity target for audit)

Authorized research / authorized-engagement use only.
