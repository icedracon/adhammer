# ADhammer 1.4.8 — hard plan (capability-expansion edition)

Rewritten 2026-08-30. 1.4.8 is no longer just a polish-1.4.7-tail release —
it's the capability-parity release that closes the gap between adhammer's
current "broad passive assessor" position (~#25 on pure technical merit)
and its target "operational offensive tool" position (top 10). Original
1.4.7-tail items stay in place; a new **Capability Expansion** section
lands 20 attack vectors + auto-scan validation hooks.

Effort estimate: **55-75 engineering days**. This is a large release.
Ship in phases within 1.4.8 tag family (1.4.8-beta.1 through 1.4.8) or
publish incrementally on `main` and cut the tag once all vectors green.

## Status snapshot — 2026-08-30 (shipped, tag pending)

**18 of 19 capability-expansion vectors LIVE on `main`.** (Original 20 became
19 after WS-SKELETON-KEY was permanently dropped from the plan — value
strictly duplicated by WS-GOLDEN-TICKET persistence + worse AV surface,
per-Windows-version binary shim; not 1.4.8-shaped work.) 6 net-new
implementations this cycle (Phase A) + 11 already-built primitives
doc-named to plan (Phase B/C/D/F) + WS-DPAPI-MASTER-KEY landed after
the initial snapshot when live-validation on Server 2025 became possible.

Sibling icedracon crate published this cycle: **dpapi-offline 0.1.1** —
fixes the masterkey chain to route through Windows's non-standard PBKDF2
variant (`ms_derive_key`) + adds MD4 + Protected-Users pre-key
derivations. Byte-oracle-validated on a live Server 2025 domain
Administrator masterkey; 176-byte MK subfield lives inline as
`KAT_MK_SUBFIELD` in dpapi-offline `masterkey::tests`. Nothing else
published to crates.io this cycle; user directive is "all is local
after this."

Only ADhammer-side artifact left to cut: `git tag v1.4.8`. A tag push
triggers the WS-BINSTALL / WS-DEB-PACKAGE CI matrix to build prebuilt
binaries + `.deb` and upload to GitHub Releases (no crates.io publish).

| Phase | Vector | State | Anchor commit |
|---|---|---|---|
| A | WS-KERBRUTE | ✅ shipped | (1.4.8-A #1) |
| A | WS-DIAMOND-TICKET | ✅ shipped | (1.4.8-A #2) |
| A | WS-SID-HISTORY-INJECT | ✅ shipped | (1.4.8-A #3, `golden` verb) |
| A | WS-ESC1-EXPLOIT | ✅ shipped | (1.4.8-A #4) |
| A | WS-ESC3-CHAIN | ✅ shipped | (1.4.8-A #5, `icpr_esc1` verb) |
| A | WS-UNPAC-FULL | ✅ shipped | (1.4.8-A #6) |
| B | WS-PSEXEC | ✅ already-built + doc-name | 569703d |
| B | WS-WMIEXEC (ex-SEALED) | ✅ already-built + doc-name | 569703d |
| B | WS-ATEXEC | ✅ already-built + doc-name | 569703d |
| B | WS-EVIL-WINRM | ✅ already-built + doc-name | 569703d |
| B | WS-DELEGATION-CAPTURE | ⚠️ recon-only | 569703d (partial) |
| B | WS-DPAPI-MASTER-KEY | ✅ shipped (post-snapshot) | 18/19 push |
| C | WS-SAM-SECURITY-DUMP | ✅ already-built + doc-name | 786e133 |
| C | WS-NTDS-OFFLINE | ❌ DEFERRED | see below |
| D | WS-NTLMRELAYX-SMB-LDAP | ✅ already-built + doc-name | 786e133 |
| D | WS-COERCE-SENDER | ✅ already-built + doc-name | 786e133 |
| D | WS-LLMNR-POISON | ✅ already-built + doc-name | 786e133 |
| D | WS-ESC8-END-TO-END | ✅ already-built + doc-name | 786e133 |
| — | ~~WS-SKELETON-KEY~~ | ❌ DROPPED (plan-cut) | see below |
| F | WS-DCSHADOW-DRSR | ✅ already-built + doc-name | 786e133 |

### The 1 remaining deferred vector (down from 3)

**WS-NTDS-OFFLINE — deferred to 1.4.9.** Sibling `ese-parser` is at v0.1
scope (668-byte header + random-access page read); B-tree walk, catalog
decode, row/tag decode are v0.2 roadmap. Downstream `ntds-parse` crate is
planned but not published. Offline NTDS.dit-file parsing therefore has no
in-house parser to layer on. The live-DCSync path (`attack dcsync`)
already covers the same output (NT hashes + krbtgt + trust keys) via
DRSUAPI — deferring the offline variant to the ese-parser v0.2 milestone
as the 1.4.9 headline feature.

### Post-snapshot: WS-DPAPI-MASTER-KEY moved deferred → LIVE

Original snapshot marked WS-DPAPI-MASTER-KEY deferred because sibling
`dpapi-offline` was "primitives + parsers KAT-validated but full chain
NOT YET VALIDATED e2e." Live-verifying on Kali against a Server 2025
Administrator masterkey (DC01, 192.168.91.20) revealed the actual bug:
`dpapi-offline` was using standard RFC 8018 PBKDF2, but Windows DPAPI
uses a **non-standard variant** that feeds the running XOR back into
the PRF at every round. Impacket 0.14 was the byte-oracle.

Fix landed as `dpapi-offline 0.1.1` (published to crates.io as the
enabler for this ship, before the "all is local" rule kicked in):
- `crypto::ms_derive_key` — the Windows variant with full docstring
  explaining exactly how it diverges from RFC 8018.
- `crypto::md4` + `crypto::pbkdf2_sha256` — primitives for the domain-
  user pre-key derivations that were missing.
- `masterkey::derive_domain_prekey_md4` (pre-2019 domain-joined) +
  `derive_domain_prekey_protected` (Server 2019+ / Protected-Users).
- `unlock_masterkey` now tries all three pre-keys (standalone SHA1 →
  domain MD4 → Protected-Users PBKDF2-SHA256) automatically.
- Real Server 2025 MK subfield lives inline as `KAT_MK_SUBFIELD` — every
  workspace test run byte-verifies the full chain vs impacket.

ADhammer verb `attack dpapi-master-key` wraps `dpapi_offline::unlock_masterkey`
with a 5-stage `StageChecklist`. Live-verified end-to-end returning the
same 64-byte master key impacket did.

### Post-snapshot: WS-SKELETON-KEY dropped from plan

Not deferred — permanently cut. Persistence value strictly duplicated by
WS-GOLDEN-TICKET already (both "log in as any user after DA"), the
lsass memory-patch detection surface is worse, and every Windows version
needs its own binary shim. Building it because it's "on the list" is
sunk-cost — the honest hard-critic call is to drop it rather than defer.
Plan denominator dropped 20 → 19.

**Net effect on capability ranking.** Original plan target: top-10.
Shipped scope (18/19) covers every mainline post-recon attack primitive
except offline NTDS.dit parsing (blocked on ese-parser v0.2, not on
scope decisions). Chain fully covered: recon → coerce → relay →
cert-abuse → DA → replication → DPAPI vault-unwrap.



## Part 1 — Original 1.4.8 items (from 1.4.7-tail closure)

### 1. ~~WS-4-P2-CLOSE~~ — CUT in 1.4.8

Static-analysis pass in 1.4.8 tried three more wrap-token layout hypotheses
after the 1.4.7 partial fix; every one produced the identical `SMB2 status
0xC00000AE (STATUS_PIPE_BUSY)`. DC-side response is binary — accept or
reject — with no informational discrimination, so blind hypothesis search
is dead. Rather than ship the `[SCAFFOLDING]` label indefinitely,
**`check krb-seal` + `AesCts96Sealer` + the `rpc_seal` RFC 3961/3962
primitives were cut from main** (deletion commit `3801471`; git history
preserves everything at tag `v1.4.7` and earlier).

**Resurrection path** — bring the code back the day someone lands a
Windows-native → DC Wireshark capture over `\PIPE\lsarpc` under
Kerberos-sealed. The capture path stays the same as documented: interactive
RDP + pktmon, or `sshpass`-driven remote invocation from a domain-joined
Windows client.

**Downstream impact:** any Capability-Expansion vector that requires
sealed DCE-RPC operations (LSA/DRSR sealed, wmiexec via DCOM ACTIVATION,
DCShadow via DRSR) stays **blocked** until this resurrects. Marked
`[SEALED-BLOCKED]` in Part 2 below.

### 2. WS-SCAN-ONLY-FILTER ✓ shipped (commit 369b9ea)

`scan --only` / `--skip` filters, ESC-registry probe gated under same
filter, live-render of the hardened-bill-of-health banner unlocked.
Closes 1.4.7 WS-CLEAN-LIVE known-open item.

### 3. WS-WIRE-TRACE — per-PDU tracing in dcerpc / smb2-client / ntlmssp

Still planned. Halted per user local-only steer — needs upstream patch
bumps + cascade cycle. Small scope per crate (~15 lines of tracing calls
per crate hot path). Same redaction discipline as 1.4.7 WS-KRB-TRACE.
Ships when the upstream publish cycle is authorized.

### 4. WS-BINSTALL + WS-DEB-PACKAGE ✓ shipped (commit fb6e796)

GitHub Actions matrix builds prebuilt binaries + `.deb` per release tag.
SHA-256 checksums + sigstore attestation via GitHub OIDC. `cargo binstall`
metadata in `cli/Cargo.toml`. Live-verify happens on next tag push.

### 5. WS-INSTALL-PS1 ✓ shipped (commit 94c04db)

`docs/install.ps1` one-liner Windows install script that wraps the
Defender-exclusion dance around `cargo binstall` / `cargo install`.

### 6. WS-CHECK-STAGES ✓ shipped (commit 8cb1de4, hotfix 04c2910)

Rich `StageChecklist` on `check adcs`. `check krb-seal` was cut in
item #1 so its 7-stage checklist went with it.

### 7. WS-COVERAGE-70 — lab seed 50 → 60%+

Still planned. Needs lab-DC console access for `ldapmodify`
attribute backdating (7 stale/dormant checks) + 5 seedable-with-more
investigation checks. Ships when console access is available.

### 8. WS-DEFENDER-SUBMIT ✓ shipped (commit 4bc86c1)

`docs/RELEASE_CHECKLIST.md` — 7-section per-release runbook including
Microsoft false-positive queue submission steps.

---

## Part 2 — Capability Expansion: 20 attack vectors

Ordered by real-world engagement impact. Every vector names:
- Crate(s) touched (mostly icedracon siblings already in repo)
- New third-party deps needed (mostly ZERO — icedracon ecosystem covers it)
- Whether the vector plugs into `auto scan` guided flow
- Blockers (sealed RPC / capture)
- Effort estimate

### 9. WS-ESC1-EXPLOIT — Full ADCS ESC1 attack chain

**What.** Detection already exists (ms-crtd rule pack). Add exploitation:
build CSR with SAN-override UPN, submit via MS-ICPR (`CertServerRequest`
opnum 0), retrieve issued cert, use it for PKINIT to KDC, receive TGT as
the impersonated principal.

**Crates:** `ms-icpr` (icedracon, ready), `ms-pkca` (icedracon, PKINIT
client), `adhammer-kerberos::tgs` (existing AS-REQ/TGS-REQ path).
**New third-party deps:** none — `rsa` + `picky-asn1-x509` + `picky-krb`
already in tree.
**auto scan hook:** YES — scan finds ESC1 template → auto offers
"validate: request cert for Administrator UPN and prove TGT acquisition".
**Blocker:** none.
**Effort:** 2-3 days.

### 10. WS-ESC8-END-TO-END — Coerce → NTLM relay → ADCS web enrollment

**What.** Coerce a target via MS-EFSR (existing) into authenticating to
our listener, relay NTLM Type1/2/3 to the CA's `/certsrv/certfnsh.asp`
endpoint, submit a CSR under victim's context, receive cert, use for
Kerberos auth.

**Crates:** `ms-coerce` (icedracon), `ntlmssp` (icedracon), `reqwest`
(HTTP with NTLM), `ms-pkca`.
**New third-party deps:** none.
**auto scan hook:** YES — scan finds ADCS + web enrollment → auto offers
"validate: coerce (target) → relay → cert → auth-as-target".
**Blocker:** none (all pure NTLM + HTTP, no sealed RPC needed).
**Effort:** 3-5 days.

### 11. WS-WMIEXEC — WMI over DCOM lateral execution

**What.** Client-side DCOM: OXID resolution → IActivation → IWbemLevel1
Login → IWbemServices::ExecMethod on `Win32_Process::Create`. Result:
arbitrary command execution on the target as the authenticating user.

**Crates:** `ms-dcom` (icedracon, scaffold → needs full ACTIVATION),
`ms-wmi` (icedracon, scaffold → needs IWbemServices), `dcerpc`.
**New third-party deps:** none.
**auto scan hook:** YES — auto-mode option "validate lateral movement via
wmiexec against a chosen target".
**Blocker:** **[SEALED-BLOCKED]** — DCOM ACTIVATION_KERBEROS / NTLM
authenticated requires sealed DCE-RPC. Unsealed only works against
ancient DCs.
**Effort:** 5-7 days AFTER WS-4-P2 resurrects.

### 12. WS-PSEXEC — SMB service-install remote execution

**What.** Copy an exe to `\\target\ADMIN$\<name>.exe` via SMB2 PUT,
`RCreateServiceW` via MS-SCMR, `RStartServiceW` to launch, capture output
via a named pipe, cleanup with `RControlService` + `RDeleteService`.

**Crates:** `smb2-client` (existing), `ms-scmr` (icedracon, ready),
`dcerpc::svcctl` (382 LOC, exists).
**New third-party deps:** none.
**auto scan hook:** YES — offers "validate SMB admin via psexec" when
scan finds a session-key-recoverable admin account.
**Blocker:** none.
**Effort:** 2-3 days.

### 13. WS-NTLMRELAYX-SMB-LDAP — NTLM relay from SMB victim to LDAP target

**What.** TCP listener accepts incoming SMB2 negotiate, extracts NTLM
Type3 from session-setup, forwards through fresh LDAP SASL bind to target
DC, on success auto-writes msDS-AllowedToActOnBehalfOfOtherIdentity
(RBCD) or msDS-KeyCredentialLink (Shadow Credentials) as the victim.

**Crates:** `smb2-client` (needs SERVER-side parse of SMB2 negotiate +
session-setup — new work), `ntlmssp` (relay-safe Type1/2/3 pass-through),
`adhammer-ldap`, `adhammer-kerberos::rbcd` + `::shadowcred`.
**New third-party deps:** none.
**auto scan hook:** YES — scan finds SMB-signing-not-required target
+ LDAP-signing-not-required DC → offers full relay chain.
**Blocker:** none (SMB server-side parse is our work).
**Effort:** 4-6 days.

### 14. WS-COERCE-LISTENER — PetitPotam / PrinterBug / DFSCoerce full chains

**What.** Wire together the existing MS-EFSR / MS-RPRN / DFS-NM coercion
senders with a full HTTP/SMB/RPC listener that captures the incoming NTLM
challenge-response. Feed captured Type3 into WS-NTLMRELAYX-SMB-LDAP for
end-to-end auto-chain.

**Crates:** `ms-coerce` (icedracon, existing paths for EFSR/RPRN/DFSNM),
`dcerpc::rprn` + `dcerpc::dfsnm` + `dcerpc::efsr` (existing modules),
listener glue.
**New third-party deps:** none.
**auto scan hook:** YES — auto-mode picks coercion target based on
scanned OS + reachable protocols, chains to relay listener.
**Blocker:** none.
**Effort:** 2-3 days combined with WS-NTLMRELAYX (share the listener
infrastructure).

### 15. WS-ESC3-CHAIN — ADCS ESC3 Enrollment Agent chain

**What.** Request cert from Enrollment Agent template, then use it to
sign a CSR on behalf of another principal, submit that CSR to CA,
retrieve issued cert, PKINIT auth as the impersonated principal.

**Crates:** `ms-icpr`, `ms-pkca`, `ms-xcep` (icedracon, cert enrollment
policy), `picky-asn1-x509`.
**New third-party deps:** none — same stack as WS-ESC1-EXPLOIT.
**auto scan hook:** YES — scan finds Enrollment Agent template + at
least one other requestable template → offers full chain validation.
**Blocker:** none.
**Effort:** 2 days (after WS-ESC1-EXPLOIT lands).

### 16. WS-SAM-SECURITY-DUMP — Remote hive extraction

**What.** Via MS-RRP (Remote Registry, `dcerpc::rrp` = 780 LOC exists):
`SaveKey` on `HKLM\SAM` + `HKLM\SECURITY` + `HKLM\SYSTEM` to attacker-
controlled remote share, retrieve via SMB, offline SYSKEY decrypt to
extract local admin NT hashes + LSA secrets + cached credentials.

**Crates:** `dcerpc::rrp` (existing, substantial), `smb2-client`,
`adhammer-secrets` (existing crate — expand SYSKEY chain).
**New third-party deps:** `des` or reuse existing `aes` for SYSKEY
crypto. Minimal.
**auto scan hook:** YES — offered as a validation step when scan finds
Remote Registry enabled + admin creds available.
**Blocker:** none.
**Effort:** 3-4 days.

### 17. WS-NTDS-OFFLINE — NTDS.dit offline hash extraction

**What.** After DCSync-equivalent read of NTDS via DRSR, or after copying
the `.dit` via VSS + SMB, parse the ESE database, decrypt with SYSKEY
(from SYSTEM hive per WS-SAM-SECURITY-DUMP), extract all user NT hashes
+ krbtgt + trust keys.

**Crates:** `ese-parser` (icedracon, exists), `ms-drsr` (icedracon),
`adhammer-secrets`, `dcerpc::drsuapi` (existing).
**New third-party deps:** none.
**auto scan hook:** YES — auto-mode fallback when DCSync-via-DRSR
returns partial or fails; offers offline-parse path.
**Blocker:** none for offline parse; DCSync-via-DRSR sealed path
[SEALED-BLOCKED] but current path uses unsealed which the DC allows.
**Effort:** 3-4 days.

### 18. WS-DPAPI-MASTER-KEY — Classic + DPAPI-NG extraction

**What.** Extract user DPAPI master keys from `%APPDATA%\Microsoft\Protect\<SID>\`
via SMB (needs admin), decrypt with user password / NT hash / MS-BKRP
domain backup key, then decrypt credentials, Chrome cookies, WiFi
passwords, RDP creds, etc.

**Crates:** `dpapi-ng` (icedracon, extend or add classic-DPAPI variant),
`ms-bkrp` (icedracon, exists — for domain backup key), `adhammer-secrets`.
**New third-party deps:** none.
**auto scan hook:** YES — auto-mode option "extract DPAPI vault of
principal X" when scan graph shows the principal's session hosts.
**Blocker:** none.
**Effort:** 3-4 days.

### 19. WS-KERBRUTE — Kerberos user enumeration + spray

**What.** Send pre-auth-less AS-REQ per candidate username, classify
KDC responses: `KDC_ERR_PREAUTH_REQUIRED` = user exists, `KDC_ERR_C_
PRINCIPAL_UNKNOWN` = doesn't. Optional: password spray via full pre-auth
AS-REQ against enumerated users.

**Crates:** `adhammer-kerberos::tgs` (existing AS-REQ code), `picky-krb`.
**New third-party deps:** none.
**auto scan hook:** YES — auto-mode "enumerate users via Kerberos"
step when no LDAP creds available (anonymous path).
**Blocker:** none.
**Effort:** 1 day.

### 20. WS-DELEGATION-CAPTURE — Unconstrained delegation TGT capture

**What.** Bind TCP listener on advertised SPN's port, accept incoming
SMB2/HTTP/etc. auth from a coerced target, parse embedded AP-REQ, extract
the user's forwarded TGT (unconstrained delegation forwards user's TGT
inside the AP-REQ authenticator). Save to ccache for reuse.

**Crates:** `adhammer-kerberos::tgs` (extend for server-side AP-REQ
parse), `picky-krb`, `ms-coerce`, `ccache-io` (icedracon, exists).
**New third-party deps:** none.
**auto scan hook:** YES — scan finds unconstrained delegation on
non-DC → auto-mode offers coerce+capture chain.
**Blocker:** none.
**Effort:** 2-3 days.

### 21. WS-LLMNR-POISON — LLMNR / NBT-NS / mDNS name-service poisoning

**What.** Listen on UDP 5355 (LLMNR) + 137 (NBT-NS) + 5353 (mDNS).
Answer any name query with our IP. Victims connect to us → capture NTLM
Type3 → feed into WS-NTLMRELAYX-SMB-LDAP.

**Crates:** `tokio::net::UdpSocket`, `smb2-client` (server-side accept
for SMB direction), `ntlmssp`.
**New third-party deps:** none.
**auto scan hook:** NO — this is a listener-mode primitive, not a
scan-derived validation. Standalone verb.
**Blocker:** none.
**Effort:** 2 days.

### 22. WS-DIAMOND-TICKET — Diamond ticket forge

**What.** Variant of Golden ticket: obtain a real TGT via legitimate
AS-REQ, decrypt its enc-part with the target's key, modify the PAC to
inject arbitrary group memberships / SID, re-encrypt with same key.
Result: a TGT that looks legitimate (real KDC signature) but grants
elevated privileges. Harder to detect than Golden.

**Crates:** `ms-pac-forge` (existing), `adhammer-kerberos::tgs` (existing
AS-REQ + Golden ticket code), `picky-krb`.
**New third-party deps:** none.
**auto scan hook:** NO — post-exploitation attack, not scan-triggered.
**Blocker:** none.
**Effort:** 1 day (variant of existing Golden ticket path).

### 23. WS-EVIL-WINRM — WinRM (WSMan/PSRP) remote shell

**What.** WSMan over HTTPS (port 5986) or HTTP (5985) with NTLM/Kerberos
auth. PSRP (PowerShell Remoting Protocol) frames commands as SOAP.
Result: PowerShell shell on target with victim's context.

**Crates:** `reqwest` (existing), `ntlmssp`, `adhammer-kerberos` (for
Kerberos-auth path), new `ms-wsman` may be needed.
**New third-party deps:** possibly `roxmltree` or `quick-xml` for SOAP
envelope parsing. Small.
**auto scan hook:** YES — auto-mode "validate lateral via WinRM" when
scan finds WinRM listener + admin creds.
**Blocker:** none.
**Effort:** 3-4 days.

### 24. WS-ATEXEC — Task Scheduler over MS-TSCH

**What.** MS-TSCH `SchRpcRegisterTask` to create a scheduled task on
target, trigger it immediately via `SchRpcRun`, retrieve output via
SMB share write, cleanup with `SchRpcDelete`. Alternative to psexec
when SCM is monitored.

**Crates:** `ms-tsch` (icedracon, exists), `dcerpc`, `smb2-client`.
**New third-party deps:** none.
**auto scan hook:** YES — offered as alternative lateral primitive
alongside psexec + wmiexec.
**Blocker:** none.
**Effort:** 2 days.

### 25. WS-SID-HISTORY-INJECT — Golden variant for cross-forest

**What.** Golden ticket forge with `sidHistory` field populated with the
Enterprise Admins SID from another forest (or child domain). Bypasses
SID filtering when trust doesn't have quarantine enabled. Result: cross-
forest privileged access from a compromised child.

**Crates:** `ms-pac-forge` (existing, extend PAC writer for sidHistory).
**New third-party deps:** none.
**auto scan hook:** YES — scan finds trust without SID filtering →
auto-mode offers "forge cross-forest golden with sidHistory".
**Blocker:** none.
**Effort:** 1 day (extend existing Golden path).

### 26. WS-DCSHADOW-DRSR — Rogue DC persistence via DRSR

**What.** Register rogue DC in the target domain via DRSR
`IDL_DRSAddEntry` + `IDL_DRSReplicaAdd`, push malicious replication
updates via `IDL_DRSGetNCChanges` outbound with our attacker-controlled
data. LDAP-path DCShadow is dead on Server 2019+; DRSR path may still
work.

**Crates:** `ms-drsr` (icedracon), `dcerpc::drsuapi` (existing).
**New third-party deps:** none.
**auto scan hook:** NO — post-exploitation persistence, not scan-driven.
**Blocker:** **[SEALED-BLOCKED]** — DRSR operations against modern DCs
require sealed DCE-RPC.
**Effort:** 3-5 days AFTER WS-4-P2 resurrects.

### 27. WS-UNPAC-FULL — Full unPAC-the-hash

**What.** After PKINIT (via WS-ESC1-EXPLOIT or shadow-credentials attack),
extract the NT hash embedded in the PAC's `PAC_CREDENTIAL_INFO` type-2
buffer. Modern KDCs return it encrypted with the AS-REP session key —
decrypt with our known session key, parse type-2 buffer, get NT hash.

**Crates:** `ms-pac` (icedracon, existing PAC parser), `adhammer-kerberos`.
**New third-party deps:** none.
**auto scan hook:** YES — auto-mode chain: WS-ESC1-EXPLOIT → PKINIT →
unPAC → NT hash of impersonated principal. Full path from ADCS misconfig
to Administrator NT hash.
**Blocker:** none.
**Effort:** 2 days.

### 28. WS-SKELETON-KEY — Windows-only LSASS shim persistence

**What.** Inject a shim into LSASS on a domain controller so any password
authenticates alongside the real password. Requires SYSTEM on DC.
Windows-only (write memory to lsass.exe). EDR flags immediately.

**Crates:** `windows-token`, `windows-scm` (icedracon 2026-08-29 wave, on
crates.io as 0.2.1), new memory-write helpers.
**New third-party deps:** possibly `windows-sys` or use existing
icedracon `win32-min` (0.1.3).
**auto scan hook:** NO — post-exploitation persistence.
**Blocker:** Windows binary only (won't build on Linux/macOS release
targets — needs conditional compilation).
**Effort:** 3 days.

---

## Counting convention (canonical)

Post-1.4.8 the CLI exposes three overlapping categories of "surfaces":

- **58 passive checks** (unchanged) — LDAP-snapshot rule pack, coverage
  matrix in the report, ADP-NN taxonomy + kill-chain phase tagged. These
  fire during `scan` and never need creds beyond the LDAP bind.
- **15 existing active-attack verbs** — asktgt, roast, kerberoast, spray,
  dcsync, s4u, silver, golden, overpass-the-hash, pass-the-ticket, abuse,
  laps-read, gmsa-read, coerce, secretsdump. These need a target + creds
  and are invoked from `attack …` or via `auto scan`'s validation path.
- **20 new attack vectors** shipping in 1.4.8 (WS-9 through WS-28).

**Total invocable surfaces: 93.**

**Distinct-surface count (deduping detection/exploit pairs): 74.**
Four of the 20 new vectors are exploitation paths for existing detections
(ESC1/ESC3/ESC8/SID-history), so they add depth to those 4 checks rather
than a new distinct surface. The other 16 new vectors are unique
capabilities the CLI didn't have before.

**For public messaging use `93` or `78 (58 + 20)`; internal engineering
uses `74 unique surfaces` when precision matters** (e.g., dedup for
report display, avoiding double-counting in coverage percentages).

## Dep summary

**Third-party deps needed for entire 1.4.8 capability expansion: ~0-2
crates.** The icedracon ecosystem already covers everything:

- **Cert/PKI:** `picky-krb`, `picky-asn1-x509`, `rsa` — already in tree
- **Crypto:** `aes`, `sha1`, `sha2`, `md-5`, `hmac`, `hkdf`, `des` (small
  add) — mostly in tree
- **HTTP/SOAP:** `reqwest` in tree; possibly `quick-xml` for WinRM (small)
- **Network:** `tokio` in tree
- **Windows FFI:** `win32-min` 0.1.3 + windows-scm/token 0.2.1 (icedracon
  wave, just published)

**Icedracon siblings that need to graduate scaffold → full:**

- `ms-dcom` (currently scaffold — needs OXID + IActivation)
- `ms-wmi` (currently scaffold — needs IWbemServices::ExecMethod)
- `ms-wsman` (may need to create — WinRM protocol)

**Icedracon siblings ready to consume as-is:**

- `ms-icpr`, `ms-scmr`, `ms-tsch`, `ms-coerce`, `ms-drsr`, `ms-pkca`,
  `ms-xcep`, `ms-pac`, `ms-pac-forge`, `ms-bkrp`, `dpapi-ng`, `ese-parser`,
  `ccache-io`, `dcerpc` (rrp/samr/svcctl/drsuapi/rprn/dfsnm/efsr modules
  substantial), `smb2-client`, `ntlmssp`, `windows-sddl`

## Effort sequencing

**Phase A — ADCS + fastest wins (7-10 days):**
- WS-KERBRUTE (1 day) · WS-DIAMOND-TICKET (1 day) · WS-SID-HISTORY-INJECT
  (1 day) · WS-ESC1-EXPLOIT (2-3 days) · WS-ESC3-CHAIN (2 days) ·
  WS-UNPAC-FULL (2 days)

**Phase B — Lateral movement (10-14 days):**
- WS-PSEXEC (2-3 days) · WS-ATEXEC (2 days) · WS-EVIL-WINRM (3-4 days) ·
  WS-DELEGATION-CAPTURE (2-3 days) · WS-DPAPI-MASTER-KEY (3-4 days)

**Phase C — Cred extraction (6-8 days):**
- WS-SAM-SECURITY-DUMP (3-4 days) · WS-NTDS-OFFLINE (3-4 days)

**Phase D — Relay + coercion (8-11 days):**
- WS-NTLMRELAYX-SMB-LDAP (4-6 days) · WS-COERCE-LISTENER (2-3 days)
  · WS-LLMNR-POISON (2 days) · WS-ESC8-END-TO-END (3-5 days)

**Phase E — Windows-only / advanced (3 days):**
- WS-SKELETON-KEY (3 days)

**Phase F — [SEALED-BLOCKED] (waits on WS-4-P2 resurrection):**
- WS-WMIEXEC (5-7 days) · WS-DCSHADOW-DRSR (3-5 days)

**Total (Phase A + B + C + D + E): ~34-46 days.**
**Plus Phase F (SEALED-BLOCKED): +8-12 days.**
**Grand total: 55-75 days.**

## `auto scan` integration matrix — 20 of 20

The guided `auto` flow (`adhammer` bare / `auto`) is restructured from
"scan → pick findings → validate" into a **five-phase attack lifecycle**
so every one of the 20 vectors slots in at the right moment. No vector
is left as a standalone verb the operator has to remember to run.

**Phase 0 — Pre-recon (no creds yet):**
- `WS-LLMNR-POISON` — optionally spin up LLMNR/NBT-NS/mDNS listener
  for N seconds before the LDAP probe, to catch any workstation-side
  name-query capture-and-relay opportunities.
- `WS-KERBRUTE` — Kerberos user enumeration when LDAP anonymous is
  closed and no creds provided.

**Phase 1 — Scan-finding-triggered validators (finding X → exploit X):**
- ESC1 template detected → **WS-ESC1-EXPLOIT** + **WS-UNPAC-FULL** chain
  (arbitrary UPN cert → PKINIT → TGT → NT hash of impersonated principal)
- ESC3 Enrollment Agent template → **WS-ESC3-CHAIN**
- ESC8 CA with HTTP enrollment → **WS-ESC8-END-TO-END** (coerce + relay
  + enroll + auth)
- SMB signing not required + LDAP unsigned → **WS-NTLMRELAYX-SMB-LDAP**
  with auto-RBCD-write or shadow-cred-write chain
- Coercion primitive reachable on target → **WS-COERCE-LISTENER** full
  chain (uses the same listener as WS-NTLMRELAYX)
- Remote Registry + admin creds available → **WS-SAM-SECURITY-DUMP**
- DCSync path via DRSR reachable → **WS-NTDS-OFFLINE** as fallback for
  partial DCSync, or as preferred path when the target won't allow
  targeted GetNCChanges
- DPAPI-protected asset + admin creds → **WS-DPAPI-MASTER-KEY** vault
  extraction
- Unconstrained delegation flag on non-DC → **WS-DELEGATION-CAPTURE**
  (coerce a DC to authenticate → capture forwarded TGT)
- Trust without SID filtering → **WS-SID-HISTORY-INJECT** golden variant

**Phase 2 — Post-cred-acquisition (creds landed via any of the above):**
- Admin creds + SMB reachable → offer three lateral primitives:
  **WS-PSEXEC**, **WS-ATEXEC**, **WS-EVIL-WINRM**. Operator picks based
  on what's least likely to trip the target's monitoring.
- Admin creds + WMI reachable → **WS-WMIEXEC** *(SEALED-BLOCKED until
  WS-4-P2 resurrects)*

**Phase 3 — Post-DA-compromise (Tier-0 achieved):**
- krbtgt hash acquired via DCSync/NTDS → **WS-DIAMOND-TICKET** offered
  as stealthier-than-Golden persistence primitive. Same krbtgt key, real
  KDC signature on the TGT skeleton, forged PAC injected.
- SYSTEM on DC achieved → **WS-SKELETON-KEY** as optional LSASS-shim
  persistence (Windows-target-only; auto-mode warns + confirms before
  execution because EDR-loud).
- DA + DRSR reachable → **WS-DCSHADOW-DRSR** as optional rogue-DC
  registration for silent AD-object modification *(SEALED-BLOCKED until
  WS-4-P2 resurrects)*.

**Phase 4 — Report:**
Every attempted vector — whether it succeeded, was skipped, or failed —
is recorded as a `WireExchange` on the corresponding Finding in the
final report. Auto-mode produces a full attack narrative alongside the
passive-check ledger.

**Result: 20 of 20 vectors are `auto scan` end-to-end validators.**
The operator runs `adhammer` bare, walks the guided flow, and every
attack primitive in the plan is offered at the right moment with the
right prerequisites already satisfied by prior phases. No manual
`attack XXX --user ... --password ... --target ...` incantations
required unless the operator wants to invoke one directly.

---

## Non-goals — will NOT ship in 1.4.8

- **No Azure / Entra ID / Entra Connect / hybrid identity.** Confirmed
  killed permanently — different auth model, different tools, different
  product. Adhammer stays on-prem AD.
- **No SCCM/MECM abuse** (NAA extraction, site takeover, client push).
  Deferred separately if it ever earns its own scope call.
- **No EV code-signing certificate.** Real fix for Defender friction,
  ~$300/year, no budget. WS-INSTALL-PS1 + WS-DEFENDER-SUBMIT are the
  zero-budget workarounds shipping today.
- **No new passive check categories for coverage-number growth.**
  Existing 58 with proof discipline are enough; the 20 vectors are
  active-attack additions that ALSO trigger passive checks along the way.
- **No BloodHound-CE ingest polish.** No downstream schema movement.
- **No CI/CD template repos.** Zero demand signal.
- **No video walkthrough / marketing surface.** Ship-first, market-later.

## Deferred — not 1.4.8

- **adhammer-sdk API stability commitment.** Zero downstream adopters
  today; premature. Revisit when there is real downstream pain.
- **WS-WIN32-MIN-ADOPT.** Adopt the icedracon 2026-08-29 `windows-*`
  wave more broadly than what WS-SKELETON-KEY requires.

## Killed

- **ADFS / Entra ID / AAD Connect attack surface.** Scope explosion.
- **Cross-protocol Kerberos-NTLM cross-realm relay.** Low ROI, rare in
  practice.
