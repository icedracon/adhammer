# ADhammer — Vector Coverage & Roadmap

Status key:

| Symbol | Meaning |
|--------|---------|
| ✅ | Closed — implemented and live-validated (or unit-tested where passive-only) |
| 🔶 | Partial — detection or trigger exists; exploit chain incomplete |
| ❌ | Open — not implemented |
| 🚫 | Out of scope — requires different tooling or active relay not in passive audit |

Last updated: 2026-07-22 · v0.0.1

---

## Quick summary

| Area | Closed | Partial | Open |
|------|--------|---------|------|
| Audit checks (33 rules) | 31 | 2 | 0 |
| AD CS ESC (passive LDAP) | ESC1/2/3/4/9/13 | ESC15/EKUwu reserved | ESC5/6/7/8/10/11 |
| Offensive CLI | 13 modes | 3 chains | ~20+ vectors |
| Protocol stack | NDR·RPC·NTLM·SMB2·Kerberos core | DRSUAPI single-object | SVCCTL·TSCH·RRPM·NETLOGON… |

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
| ESC5 | Vulnerable PKI object ACL (CA server) | ❌ | Needs CA `nTSecurityDescriptor` + enrollment service ACL audit beyond templates |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | ❌ | Requires CA registry / `pKIEnrollmentService` flags not in LDAP today |
| ESC7 | Vulnerable CA ACL (ManageCa / ManageCertificates) | ❌ | CA object ACL parse not wired |
| ESC8 | Web Enrollment HTTP relay | 🚫 | Active NTLM relay to `http://…/certsrv` — detection only possible via port 80/443 sweep |
| ESC9 | CT_FLAG_NO_SECURITY_EXTENSION + auth EKU | ✅ | |
| ESC10 | Weak certificate mapping on DC | ❌ | Requires registry / `StrongCertificateBindingEnforcement` — not in LDAP snapshot |
| ESC11 | ICPR RPC relay | 🚫 | Active relay to `\cert` pipe (similar to ESC8) |
| ESC13 | Issuance policy → privileged group link | ✅ | |
| ESC15 / EKUwu | Schema v1 + application policies confusion | 🔶 | `schema_version` collected; rule not implemented (`adcs.rs` reserved) |

**Offensive AD CS:** ❌ No cert enrollment, no ESC1/3 exploit, no Certipy parity.

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
| LAPS password read | Medium | Audit detects missing LAPS; no `attack laps` |
| AdminSDHolder / ACL backdoor write | Medium | Graph detects paths; no `attack dacl` helper |
| DNS ADIDNS poisoning / delegation abuse | Low | No DNS client |
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
| WINRM / WS-MAN | ❌ | Deep probe only |
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

## Suggested close order (roadmap)

1. **Pass-the-ticket** — read existing `.ccache` from PKINIT; trivial win.
2. **ESC7/ESC5 passive** — extend AD CS LDAP collection to CA objects + enrollment service ACLs.
3. **Constrained delegation** — reuse S4U code paths already in kerberos/tgs.
4. **GMSA / LAPS read** — LDAP extended rights + attribute read.
5. **SVCCTL + TSCH** — remote exec primitives (high engagement value).
6. **Cert enrollment** — close the AD CS offensive gap.
7. **ESC8/11 relay** — HTTP + ICPR clients on top of existing relay server.
8. **Full-domain DCSync** — bulk GetNCChanges + secretsdump-all.

---

## References

- [README.md](README.md) — build, architecture, live-validated flows
- [lab/README.md](lab/README.md) — WS2025 lab setup
- SpecterOps AD CS ESC definitions
- PingCastle rule categories (parity target for audit)

Authorized research / authorized-engagement use only.
