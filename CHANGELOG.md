# Changelog

All notable changes to ADhammer are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com); this project uses SemVer.

## [Unreleased]

## [1.3.9] — 2026-08-20

### Added
- **Session-hunt trio** — three complementary "who is on this box" primitives:
  `enum sessions` (MS-SRVS `NetrSessionEnum`, incoming SMB sessions),
  `enum wkssvc` (MS-WKST `NetrWkstaUserEnum` level 1, logged-on users — needs
  local admin), `enum hku` (MS-RRP registry walk over `\winreg` returning the
  S-1-5-21 SIDs of loaded profile hives — often works without local admin).
  Dedup + machine-account filter on by default.
- **Global `--json` envelope** on every `attack`/`enum`/`dump` subcommand — output
  wraps in an `AttackResult` envelope that pipes cleanly into `jq` and CI.
- **DPAPI-encrypted saved sessions on Windows** — `~/.config/adhammer/session.json`
  uses `CryptProtectData` with an `ADHS` magic header; `--old` reuses cached creds,
  `--no-save` keeps them off disk.
- **ADCS scan pack** — `scan` now runs ESC6, ESC7, ESC8, ESC10, ESC11, ESC16 as
  part of the default sweep via MS-RRP `\winreg` probes plus an HTTP probe for
  ESC8 web enrollment.
- New `dcerpc` modules: `wkssvc` (`NetrWkstaUserEnum`) and `rrp::logged_on_sids`
  (HKU walk).

### Fixed
- **Wire-stack bounded-alloc audit** — every attacker-controlled `u32` that fed
  `Vec::with_capacity` in the wire decoders is now preflighted against the
  remaining stub:
  - `srvsvc::decode_session_enum` — `entries_read × 16` preflight.
  - `rrp::decode_query_info_class` — `actual × 2` preflight.
  - `rrp::decode_enum_key` — `actual × 2` preflight.
  - `wkssvc::decode_wksta_user_enum` — `entries_read × 16` preflight.
  Regression tests feed `0xFFFFFFFF` and assert `RpcError::Protocol`. Requires
  `dcerpc 0.2.5`.

### Live-validated
Full stack against Windows Server 2022 and Server 2025 DCs.

## [1.3.8] — 2026-08-18

### Added
- **DCShadow phase-1 prep** — `attack dcshadow --prep <name>` registers a rogue
  `nTDSDSA` object under Configuration NC (idempotent; safe to re-run after
  partial failure). `attack dcshadow --cleanup <name>` removes it. Full push
  (phase 2) is not yet implemented. **Note:** the LDAP path is blocked by
  Server 2019+ "system-owned attribute" hardening; the docstring on the
  subcommand carries that caveat. Server 2016 and older accept the LDAP path.
- `Collector::delete_object` — LDAP delete primitive that DCShadow cleanup
  uses; also fills a general-purpose gap in the collector.

### Fixed
- Requires `dcerpc 0.2.4` — wire stack hardened against three bounded-alloc
  vectors uncovered in review of the incoming external PR (srvsvc + two rrp
  sites).

## [1.3.7] — 2026-08-16

### Added
- **AD CS active pack extension** — `attack certipy` (renamed to
  `attack icpr-esc1` in 1.3.10) gains `--esc` switch:
  - ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 SAN injection (live-validated).
  - ESC15 — EKUwu / CVE-2024-49019 Application Policies (live-validated).
  - ESC3 — Enrollment Agent → on-behalf-of (offline test passes; live needs
    EA cert setup).

### Fixed
- **4 library security patches** ship as pinned deps:
  - `ms-icpr 0.1.2` — fix `esc3.rs` PKIData `[0]` IMPLICIT vs EXPLICIT tagging
    (Windows CAs were rejecting the request shape).
  - `ms-pac-forge 0.1.2` — bounded-alloc preflight in `parse_pac` (caps
    attacker-controlled `c_buffers u32` at `(pac.len() - 8) / 16`).
  - `ntlm-relay 0.1.2` — drop duplicate `Host` / `Connection` / `Content-Length`
    headers on `certsrv` send sites.
  - `ms-csra 0.1.1` — delete broken `GetCAProperty` path (opnum 3 was
    `SetExtension`, not `GetCAProperty`); expose only `GetConfigEntry` on
    `ICertAdminD2` opnum 44.

### Pulled
- `enum ca-config` command — `ICertAdminD2` UUID + opnum 44 rejected by live
  DC01; needs Wireshark trace of a real `certutil -config` before re-adding.

## [1.3.6] — 2026-08-15

### Fixed
- Fix #3 (assorted patches rolled in).

## [1.3.5] — 2026-08-15

### Changed
- Workspace version bump + README refresh — no user-visible functional change;
  clears drift after the pre-1.4.0 revert.

## [1.4.0] — 2026-08-13 (YANKED)

Yanked on crates.io. Version number **retired**; the next major bump will be
`1.4.1`. Content was rolled back by commits `219a415` + `e5a8163` before
downstream users saw a working release.

## [1.3.4] — 2026-08-13

### Fixed
- `check adcs` returned 0 templates because `Collector` `ATTRS` missed the
  `msPKI-Cert-Template-OID` required by `ms-crtd`. Live-validated fix.

## [1.3.3] — 2026-08-09

### Added
- Wire ADhammer onto `ms-crtd` + `ms-icpr` + `ms-gkdi` — the AD CS ESC rule
  pack + `dump laps` / `dump gmsa` / `attack certipy` land in the CLI.

### Fixed
- CI fix for `[patch.crates-io]` — CI was picking up path-deps that don't
  exist for CI users.

## [1.3.2] — 2026-08-09

### Changed
- Consume `ms-pac-forge 0.1.1` from crates.io + wire onto the 17-crate
  icedracon foundation set (all extracted from adhammer, now published
  standalone). Adhammer is now a workspace on top of published protocol
  crates, not a monorepo.

## [1.3.1] — 2026-08-06

### Fixed
- BadSuccessor (Server 2025 dMSA) bug fix.

### Changed
- Consume `smb2-client 0.2.1` — brings `TCP_NODELAY` win on the SMB transport;
  measurable latency drop on many-small-PDU workloads (RPC-heavy scans).
- Benchmarks refreshed against the new transport perf.

## [1.2.0] — 2026-08-02

### Added
- **WMI / DCOM remote execution** (`attack wmiexec`) — a from-scratch MS-DCOM + MS-WMIO stack:
  `RemoteCreateInstance` activation → OXID-binding resolve → object-ORPC (`PFC_OBJECT_UUID`) →
  `IWbemLevel1Login::NTLMLogin` → `IWbemServices::ExecMethod Win32_Process.Create`. Runs an arbitrary
  command detached under WmiPrvSE, captures output over C$; **password or pass-the-hash**. No service
  or scheduled task (distinct host telemetry from `exec`/`atexec`). Live-verified vs a Windows DC.
- **Hygiene checks → 41 total** — privileged-account, stale-object and password-policy rules
  extending the base hygiene rule set.
- **`enum esc`** — AD CS ESC6/7/10/11/16 over a from-scratch MS-RRP remote-registry client (takes ESC
  coverage to 15/16); **`enum posture`** — LDAP signing / channel binding / Spooler relay-enablers.
- **`attack zerologon`** — CVE-2020-1472 **safe detection** (never resets the machine password).
- **SOCKS5 pivot** (`--socks`) routing all outbound TCP — SMB, RPC/DCSync, LDAP collection, KDC, WinRM,
  and the network sweep — through a proxy with proxy-side DNS.
- **Legacy-DC support matrix** — live-validated on Server 2012 R2 / 2016 / 2019 / 2022 in addition to
  fully-patched 2025 (golden ticket KDC-accepted on every version).
- **Guided exploitation** (`adhammer auto`, + interactive "Guided" menu item) — scan → correlate
  findings → for each weakness **ask the operator "validate + capture a PoC?"** → run the matching
  attack (Kerberoast, DCSync, gMSA read, AD CS ESC1) → capture the exact command + output as
  evidence → write a **Markdown assessment report**. Declined and non-auto-validatable findings are
  still documented in the report (marked not-exercised), so it's the complete picture. Colored,
  severity-coded terminal output; `--yes` runs unattended. Live-validated vs Server 2025 (report
  captured a real DCSync krbtgt-hash PoC).
  - **Proof-based validation:** a finding is marked "validated" only when the specific evidence is
    present (an actual `$krb5tgs$`/`$krb5asrep$` hash, a replicated `krbtgt` secret, an `ISSUED`
    cert), checked against the full output — otherwise "attempted." No exit-code false positives.
  - **Opportunistic active checks** beyond the passive scan: LAPS local-admin read and AD CS ESC8
    web-enrollment probe, added to the report only when a weakness is confirmed (live-validated: a
    seeded LAPS password was recovered into the PoC). Coercion/relay deferred (need a capture listener).

### Changed
- **TLS backend is now a Cargo feature — rustls by default.** The default build is pure-Rust (no
  `openssl-sys`, no system libraries), so it cross-compiles cleanly and static-links (a fully static
  `x86_64-unknown-linux-musl` binary). `--no-default-features --features tls-native` selects the
  OpenSSL/Schannel backend for legacy DCs whose LDAPS certs use SHA-1 handshake signatures.

### Fixed
- **SOCKS pivot now covers LDAP collection** — ldap3 owns its own connect, so a local forwarder
  bridges it through the proxy (the `--socks` help claimed LDAP coverage that the collector bypassed).
- **S4U / service-ticket etype robustness** — `get_service_ticket` offers RC4 alongside AES256 (an
  overpass-the-hash TGT is RC4); `pa_for_user` rejects a non-AES256 TGT key with a clear error.

### CI
- **Release workflow** — cross-compiled binaries (x86_64 linux-musl static / linux-gnu / windows-msvc,
  aarch64 macOS) built and attached to the GitHub release on tag push.

## [1.1.0] — 2026-07-29

### Added
- **AD CS audit ESC5 / ESC14 / ESC15** — three new passive (LDAP-only) certificate-services checks:
  ESC5 (broad-principal Write/Owner over a CA object → PKI reconfiguration), ESC14 (weak explicit
  `altSecurityIdentities` mapping — Subject-only / Issuer+Subject / RFC822), and ESC15 / EKUwu
  (CVE-2024-49019 — any enrollable schema-v1 template allows application-policy injection). Takes
  ADhammer's ESC coverage to 10/16. ESC14 + ESC15 live-validated vs Server 2025 (ESC15 on the lab's
  v1 templates; ESC14 on a seeded weak mapping). ESC6/7/10/11/16 remain (need a CA/DC registry read).
- **AD CS enumeration + ESC8 detection** (`enum adcs`) — list enterprise CAs (name + host) from the
  Configuration NC, then actively probe each CA's `http://<host>/certsrv` web-enrollment endpoint:
  a cleartext NTLM/Negotiate 401 is flagged as ESC8 (relayable — no TLS ⇒ no channel binding). ESC8
  is relay-only so it can't be decided from the passive LDAP snapshot; this is the active check.
  Classifier unit-tested; live-validated vs Server 2025 (CA discovered; ESC8 negative without web
  enrollment, positive once the Web-Enrollment role is present). ESC11 (unencrypted ICPR) detection
  is noted as a follow-up (needs a CA config read).
- **ADIDNS enumeration** (`enum dns`) — adidnsdump-equivalent: read every AD-integrated DNS zone
  and record from the `DomainDnsZones`/`ForestDnsZones` (and legacy `System`) partitions over LDAP,
  with a from-scratch `DNS_RPC_RECORD` parser (A/AAAA/CNAME/NS/SOA/SRV/MX/TXT/PTR; unknown types as
  hex). Flags wildcard (`*`) nodes — an ADIDNS/mitm6 name-hijack surface — and tombstoned records.
  Interactive menu entry. Live-validated vs Server 2025 (zones + all record types + wildcard).
- **WinRM exec** (`attack winrm`) — run commands over WS-Management (5985/HTTP) with NTLM auth
  and MS-NLMP message encryption ("SPNEGO session-encrypted" multipart), on a from-scratch raw-TCP
  HTTP client (no external WinRM/HTTP stack). Full shell lifecycle (Create → Command → Receive
  loop → Signal → Delete), stdout/stderr capture, exit-code propagation, and pass-the-hash
  (`--nt-hash`). Quieter than SVCCTL — no 7045 service-install event. Interactive menu entry added.
  Live-validated vs Server 2025 (password + PtH, stdout/stderr, exit codes).
- **Session hygiene** — top-level `--no-save` (never write creds to disk) and a "Wipe saved
  session" interactive menu item, for use on a client/engagement box.
- **LAPS read** (`attack laps`) — recover local-administrator passwords over LDAPS. Reads both
  legacy Microsoft LAPS (`ms-Mcs-AdmPwd`, cleartext) and Windows LAPS (`msLAPS-Password`, JSON);
  `--target <HOST$>` for one host or omit it to sweep every computer whose LAPS attribute you can
  read. The DPAPI-NG-encrypted `msLAPS-EncryptedPassword` is surfaced but not yet decrypted.
  Interactive menu entry added. Live-validated vs Server 2025 (Windows LAPS, plaintext mode);
  degrades cleanly to "no LAPS readable" on DCs without the LAPS schema. First ROADMAP v1.1 item.

## [1.0.1] — 2026-07-29

### Fixed
- **Scan/roast/all LDAP actions failed on real DCs with a bare username** (`administrator`) —
  a bare sAMAccountName is rejected by simple_bind (rc=49, `data 52e`). The collector now reads
  the domain from RootDSE and auto-qualifies a bare name to a UPN (`user@domain`); anything
  already qualified (`DOMAIN\user`, UPN, full DN) is untouched. Bind errors now name the identity
  tried and suggest the qualified form instead of a bare "bind failed". Verified live vs Server 2025.
- **Interactive network sweep defaulted to `10.0.0.0/24`**, which sweeps an empty range on most
  engagements. It now defaults to the DC's own /24.

## [1.0.0] — 2026-07-28

First stable release. A single Linux-native Rust binary that both **audits** Active Directory
and **exploits** it, on a from-scratch DCE/RPC · NTLM · SMB2 · Kerberos stack. Every offensive
capability below is live-validated end-to-end against a fully-patched **Windows Server 2025** DC.

### Audit
- 33 checks across four AD hygiene categories (privileged accounts, trusts, stale objects,
  anomalies), with per-finding MITRE ATT&CK mapping.
- In-process control-path graph (reverse-Dijkstra to Tier-0); works as a
  low-privileged user via the LDAP `SD_FLAGS` control.
- BloodHound CE ingest bundle export (`scan --bloodhound`).
- SYSVOL / GPP cpassword (MS14-025) and GptTmpl.inf policy analysis.

### Offense (live-validated vs Server 2025)
- **Roasting** — AS-REP and Kerberoast (RC4 13100 + AES 19700); requests RC4 **and** AES so
  AES-only services still yield a ticket.
- **Password spray** + user/AS-REP-roastable enumeration.
- **LDAP-object abuse** — add-spn, add-member, set-password, write-rbcd, Shadow Credentials
  (`msDS-KeyCredentialLink`).
- **RBCD** and **constrained delegation** — full S4U2Self → S4U2Proxy chains.
- **Shadow Credentials PKINIT** — key-trust TGT, incl. the Server 2025 `paChecksum2`
  (SHA-256 over the KDC-REQ-BODY) requirement.
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
Extracted from this repo as reusable MS-* protocol crates:
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
- BloodHound export is confirmed to ingest + analyze in **BloodHound CE** (the domain loads as a
  queryable graph); not yet exercised across every edge type.
- Open vectors (roadmap): noPac, Zerologon, ADCS ESC5–11, DCShadow, LAPS, trust-key dumping —
  see [VECTORS.md](VECTORS.md).

Authorized testing / research / education only — see [SECURITY.md](SECURITY.md).
