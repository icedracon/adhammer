# ADhammer — Post-1.0 Roadmap

Enterprise-AD attack coverage we don't have yet, ranked by value ÷ effort. Each item lists what
it is, **why** it matters on real engagements, **reuses** (what's already in the tree so we don't
start from zero), rough **effort**, and how to **validate** it. Kill-chain phase + MITRE tag
included for mapping to a report.

> Authorized testing / research only — see [SECURITY.md](SECURITY.md).

## Kali workspace (run it on the engagement)

```sh
sudo apt-get install -y build-essential pkg-config libssl-dev   # LDAP layer links system TLS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
git clone https://github.com/icedracon/adhammer && cd adhammer
cargo build --release            # ./target/release/adhammer
# or grab the prebuilt Linux binary from the v1.0.0 GitHub release
```
Interactive for exploration (`adhammer`), subcommands for the high-stakes actions. **Wipe the
saved session after** (`rm ~/.config/adhammer/session.json` — it stores creds). Keep
impacket/netexec/certipy as proven backup.

---

## Phase B-1 — next build (spec-ready): noPac + Zerologon

The two one-shot domain-takeover CVEs reviewers expect. **Both are patched on every current DC,
including the 2025 lab** — so on the current lab they can only be *negatively* validated (the tool
must correctly report "not vulnerable / patched"). A **positive** run needs an unpatched/legacy
snapshot, so this phase pairs with the Tier-0 legacy-DC matrix; build it *with* a ≤2019 (noPac) /
≤2020 (Zerologon) box so it ships proven, per the DoD ("built but unprovable ≠ done").

### B-1a — noPac (CVE-2021-42278 + 42287)  ·  Kerberos priv-esc · T1558
sAMAccountName spoofing: a normal user (MAQ > 0) creates a machine account, renames it to a DC's
name, and gets a service ticket *as the DC* → DCSync.
1. **LDAPS create** a machine account (`objectClass=computer`, `unicodePwd`, `sAMAccountName=x$`,
   an SPN). — *needs the new object-create plumbing below.*
2. Clear the new machine's `servicePrincipalName` (so the KDC can't find it on the TGS lookup).
3. Rename `sAMAccountName` → a DC's name **without** the trailing `$` (e.g. `DC01`) — 42278.
4. AS-REQ a TGT for `DC01`.
5. Rename the machine back (or delete) → the KDC resolves the TGT's client to the real `DC01$` — 42287.
6. `s4u2self` as `Administrator` → service ticket as `DC01$`/Administrator → DCSync-capable.
- **Reuses:** `kerberos::get_tgt`/overpass, `kerberos::tgs` S4U2self, LDAP modify.
- **Build (shared plumbing):** `collector` gains **LDAP object-create + modify-replace over LDAPS**
  (ldap3 `add()` / `Mod::Replace`, incl. `unicodePwd` on a confidential channel). This is also the
  v1.2 ESC-write dependency — build once.
- **Effort:** M–L (4–5 d). **Validate:** unpatched ≤2019 DC with MAQ > 0 → DCSync as the DC.

### B-1b — Zerologon (CVE-2020-1472)  ·  Netlogon auth bypass · T1210
Netlogon AES-CFB8 with an all-zero IV: ~1/256 of the time a zero plaintext encrypts to zero, so a
zero `ClientCredential` authenticates — then reset the DC machine password to empty.
1. New **MS-NRPC (Netlogon)** RPC client over `ncacn_ip_tcp` (unauthenticated bind; the secure
   channel is app-level).
2. `NetrServerReqChallenge` with an all-zero client challenge.
3. `NetrServerAuthenticate3` with a zero `ClientCredential`, looping ≤~2000 attempts until it
   validates (the ~1/256 event).
4. `NetrServerPasswordSet2` with an all-zero encrypted password → **sets DC$'s password empty in AD**.
5. DCSync as `DC01$` with the empty password → full compromise.
- **Reuses:** `dcerpc` TCP transport + NDR. **New:** the NRPC interface marshaling + AES-CFB8
  (add the `aes` crate or hand-roll CFB8).
- **⚠️ DESTRUCTIVE:** step 4 breaks the DC's secure channel until restored. Gate behind an explicit
  `--i-understand-this-breaks-the-dc` flag; ship the **restore** path (re-set DC$ to its original
  hash) and document snapshot-rollback. **Lab-only, on a revertable snapshot.**
- **Effort:** M (~3 d; the crypto loop is small, the NRPC marshaling is the work).
  **Validate:** unpatched ≤2020 DC snapshot → auth bypass, then restore.

**Order:** build the LDAP object-create plumbing first (unblocks B-1a *and* the ESC-write class),
then B-1a, then B-1b. Stand up the legacy snapshot before claiming either "done."

---

## Tier 1 — quick, high-value, buildable now (no new lab)

### 1. LAPS read  ·  Cred-dump · T1003  ·  ✅ DONE (v1.1.0)
Read `ms-Mcs-AdmPwd` / `msLAPS-Password` (+ `msLAPS-EncryptedPassword`) over LDAPS for principals
allowed to. Ubiquitous in real domains; instant local-admin.
- **Reuses:** the gMSA path (`attack gmsa`) already does authenticated LDAPS attribute reads — clone it.
- **Effort:** S (½ day). Add `attack laps --target <host$>`; handle both legacy plaintext and the
  new encrypted-LAPS DPAPI-NG blob (encrypted needs a decrypt step — ship plaintext first).
- **Validate:** seed LAPS in the lab (`Set-AdmPwdReadPasswordPermission`), read it, PtH as local admin.

### 2. WMI exec  ·  Lateral/exec · T1047
Command execution over DCOM/WMI (`IWbemServices::ExecMethod` Win32_Process.Create) — quieter than
SVCCTL (no service/event 7045), and the go-to when psexec is flagged.
- **Reuses:** the DCE/RPC + NTLM sealed-pipe stack in `dcerpc`; output-retrieval-over-C$ from `svcctl`.
- **Effort:** M (2–3 days). DCOM is the work: IObjectExporter/IActivation + IRemUnknown + the WMI
  interfaces. Real chunk of NDR.
- **Validate:** `attack wmiexec --command whoami` → SYSTEM/user on the lab DC.

### 3. WinRM exec  ·  Lateral/exec · T1021.006  ·  ✅ DONE (v1.1.0)
PowerShell Remoting (5985/5986) — evolution-run standard, often the only lateral path allowed.
- **Reuses:** less of the RPC stack; it's HTTP(S) + SOAP/WS-Man + NTLM-over-HTTP (the `ntlmssp` crate
  gives the NTLM). New HTTP client + WSMan envelopes.
- **Effort:** M (2–3 days).
- **Validate:** `attack winrm --command whoami` against the lab (enable WinRM first).

### 4. Session hygiene (engagement-safety)  ·  —  ·  ✅ DONE (v1.1.0)
`--no-save` flag + a "Wipe session" interactive menu item so creds don't persist to disk on a
client box.
- **Effort:** S (1–2 h). Pure CLI.

---

## Tier 2 — high enterprise value, medium effort

### 5. ADCS ESC8 / ESC11 (relay → CA → cert → PKINIT)  ·  Relay/ADCS · T1649
Coerce a machine → relay its NTLM to the CA's web-enrollment (ESC8) or ICPR RPC (ESC11) → get a
cert as that machine → PKINIT → its TGT. One of the highest-impact modern paths.
- **Reuses:** we already have **both hard halves** — `relay` (NTLM relay) and `esc1` (ICPR enroll +
  cert-PKINIT via `pkinit_with_cert`). This is mostly wiring: point the relay at the CA's HTTP
  (ESC8) or `\pipe\cert` (ESC11) instead of LDAP.
- **Effort:** M (3–4 days; ESC8 needs an HTTP-NTLM relay target, ESC11 reuses the sealed ICPR client).
- **Validate:** lab CA + coerce the DC → relay → machine cert → TGT.

### 6. noPac (CVE-2021-42278/42287)  ·  Kerberos priv-esc · T1558
Create a machine acct → clear SPNs → rename its `sAMAccountName` to a DC's (no `$`) → TGT → rename
back → S4U2self → ticket as the DC (DCSync-capable). Devastating on unpatched ≤2019.
- **Reuses:** `get_tgt`/overpass, `s4u2self`, LDAP modify.
- **Blocks:** need **LDAP object-create** (machine acct) + `unicodePwd` over LDAPS — the raw `ldap`
  crate only does `modify_add` over 389; build create/modify-replace on the collector's ldap3 (TLS).
- **Effort:** M–L (4–5 days). **Patched on all current DCs** — validate on the 2008 R2 / unpatched target.

### 7. Unconstrained-delegation TGT capture  ·  Kerberos · T1558
Coerce a DC/privileged host to auth to a host we control that holds unconstrained delegation →
capture its TGT from the AP-REQ → reuse (DCSync).
- **Reuses:** `coerce` (PetitPotam/PrinterBug) + the Kerberos AP-REQ parsing. Missing piece is the
  "listener that extracts the delegated TGT."
- **Effort:** M (3 days).
- **Validate:** lab host w/ TRUSTED_FOR_DELEGATION + coerce the DC → pull DC$ TGT.

### 8. SID-history / ExtraSids in golden + cross-forest  ·  Persistence · T1134.005 / T1558.001
Inject Enterprise-Admins / a parent-domain SID into the forged PAC's `ExtraSids` → child→parent
and forest-wide escalation from one golden ticket.
- **Reuses:** the whole `pac` marshaler — just populate `SidCount` + the `ExtraSids` NDR array (we
  currently emit `SidCount=0`).
- **Effort:** S–M (1–2 days; it's the PAC NDR we already own).
- **Validate:** lab child domain, forge with parent EA SID, DCSync the parent.

---

## Tier 3 — bigger / niche (do as engagements demand)

- **mitm6 + relay→SMB** · T1557 — IPv6 DHCPv6/DNS takeover to source coerced auth; add SMB as a
  relay target (we only relay to LDAP). Effort M–L.
- **GPO abuse** · T1484.001 — edit a linked GPO (immediate scheduled task / startup script) for exec
  or persistence. We read SYSVOL; need write + GPT/GPC versioning. Effort M.
- **MSSQL exploitation** · T1210 — `xp_cmdshell`, linked-server chains, `EXECUTE AS` impersonation.
  We already fingerprint TDS; add TDS auth + query. Effort M.
- **DCShadow** · T1207 — register a rogue DC and push malicious replication. Big (DRSUAPI server side).
- **Golden certificate** · T1649 — forge a client cert with the stolen CA private key (dump CA key
  first). Effort M once CA-key theft exists.
- **ADCS ESC2/3/4/6/7/9/10/13** exploitation — audit already *detects* several; add the enroll/abuse
  per class. Effort varies (ESC4 template ACL edit is easy; ESC9/10 mapping are involved).
- **AdminSDHolder / DACL backdoor**, **user DPAPI** masterkeys, **skeleton key** (on-host, likely N/A
  for a remote tool).

---

## Tier 0 — test infrastructure (do first, ongoing)

Everything above is only "done" once proven. adhammer is live-validated **only against Server
2025** today.

- **Legacy DC matrix**: stand up **2008 R2 / 2012 R2 / 2016 / 2019 / 2022** DCs (snapshots) and run
  the suite per version — record which etypes, which ESC classes escalate, RC4 golden→TGS
  completion, `reg save` (secretsdump) behavior, signing posture. `lab/` scripts parameterise
  domain/IP. See `Project_adhammer_LegacyMatrix.md` in the vault.
- **Note on 2008 R2** (your current target): RC4 golden/silver should *complete* (unlike 2025);
  secretsdump SAM/LSA should *work* (no SeBackupPrivilege hardening); ESC1 → *full* escalation
  (no strong cert-mapping). **Shadow Credentials will NOT work** (needs 2016+ DFL).

---

## Release plan (milestones)

Grouped by *what can be proven where*, so nothing ships half-built. **Definition of done (every
item):** unit tests (spec vector / round-trip) + live-validated on a real DC + CHANGELOG entry +
README/VECTORS row + tagged release. "Built but unprovable" doesn't count as done.

### v1.1 — "Lateral & LAPS"  ·  ~1 week  ·  provable on the current 2025 lab, zero new infra
The cheapest, highest-frequency real-engagement gaps — all validatable today.
- ~~**LAPS read** (S, ½d)~~ **DONE (v1.1.0)** — `attack laps`; legacy `ms-Mcs-AdmPwd` + Windows LAPS
  `msLAPS-Password` (JSON), one host or sweep-all; live-validated vs Server 2025. Encrypted blob deferred.
- ~~**WinRM exec** (M, 2–3d)~~ **DONE (v1.1.0)** — `attack winrm`; NTLM + MS-NLMP message encryption
  over 5985 (from-scratch raw-TCP HTTP), full shell lifecycle, stdout/stderr/exit, PtH; live-validated.
- **WMI exec** (M, 2–3d) — DCOM/`IWbemServices` Win32_Process.Create; the DCOM activation is the work.
  **IN PROGRESS:** DCOM foundation landed in the `dcerpc` crate (`dcom` module) — `IObjectExporter`
  (OXID resolver, `ServerAlive` **live-validated** vs the lab) + `ORPCTHIS` + well-known IIDs/CLSIDs.
  Remaining (the bulk): `ISystemActivator::RemoteCreateInstance` + activation-properties blob →
  OXID resolution → `IWbemLevel1Login::NTLMLogin` → `IWbemServices::ExecMethod` (Win32_Process.Create,
  CIM-object marshaling) → output over SMB. **Note:** DCOM lives in standalone `dcerpc`; wiring
  `attack wmiexec` into adhammer needs a `dcerpc` 0.2 publish + workspace dep bump.
- ~~**Session hygiene** `--no-save` + wipe menu item (S, 2h)~~ **DONE (v1.1.0)**.
> Milestone goal: adhammer has ≥3 lateral-exec methods (SVCCTL/WinRM/WMI) + LAPS local-admin, all green on the 2025 lab. **SVCCTL + WinRM + LAPS shipped; WMI remains.**

### v1.2 — "ADCS depth"  ·  ~1 week  ·  provable on the lab CA
- **ESC8 / ESC11** (M, 3–4d) — wire existing `relay` → CA HTTP (ESC8) / ICPR pipe (ESC11) → `pkinit_with_cert`.
- **ESC4** template-ACL edit → then ESC1 (S, ~1d) — cheap once we're in ADCS-abuse code.
- **SID-history / ExtraSids in golden** (S–M, 1–2d) — populate the PAC `ExtraSids` array we already own (single-domain part provable now; cross-forest defers to v1.3).
- **Infra unlock:** LDAPS object-create + modify-replace on the collector's TLS ldap3 — needed here and a hard dependency for noPac. Build it in this milestone.
> Milestone goal: the modern relay→ADCS→DA path lands end-to-end on the lab.

### v1.3 — "Legacy & forest"  ·  gated on infra  ·  build *with* the target so it ships proven
Pairs with the real 2008 R2 engagement box + added DC snapshots. Don't build unprovable attack code ahead of the DC.
- **Legacy DC matrix** (Tier 0) — record scan/roast/dcsync/golden/pkinit/esc1/secretsdump/relay per version, starting 2008 R2. Fills the README support matrix + per-version integration gates.
- **noPac** — on the LDAPS object-create plumbing from v1.2; validate on unpatched ≤2019.
- **Unconstrained-delegation TGT capture** — coerce → listener extracts delegated TGT.
- **ExtraSids cross-forest** — validate child→parent with a second lab domain.
- Confirm v1.1/v1.2 features + the 2025-only extras (paChecksum2, PAC requestor) degrade cleanly on old KDCs.
> Milestone goal: README ships a real per-version support matrix, not "2025 only."

### v1.4+ — backlog (engagement-driven, no fixed date)
mitm6 + relay→SMB · GPO abuse (write) · MSSQL `xp_cmdshell`/linked-server · DCShadow · golden
certificate (needs CA-key theft) · remaining ESC2/3/6/7/9/10/13 · AdminSDHolder/DACL backdoor ·
user DPAPI masterkeys.

### Start here
**v1.1 → LAPS**, now. ½-day, reuses the gMSA read almost verbatim, and I can validate it against
the lab (seed LAPS → read → PtH as local admin) in the same session — so it ships done, not staged.
