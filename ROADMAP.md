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

## Tier 1 — quick, high-value, buildable now (no new lab)

### 1. LAPS read  ·  Cred-dump · T1003
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

### 3. WinRM exec  ·  Lateral/exec · T1021.006
PowerShell Remoting (5985/5986) — evolution-run standard, often the only lateral path allowed.
- **Reuses:** less of the RPC stack; it's HTTP(S) + SOAP/WS-Man + NTLM-over-HTTP (the `ntlmssp` crate
  gives the NTLM). New HTTP client + WSMan envelopes.
- **Effort:** M (2–3 days).
- **Validate:** `attack winrm --command whoami` against the lab (enable WinRM first).

### 4. Session hygiene (engagement-safety)  ·  —
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

## Suggested build order
Tier-1 (LAPS → WinRM → WMI → session-hygiene) closes the most common real-world gaps cheaply and
needs no new lab. Then ESC8/11 (huge, and half-built). noPac + unconstrained + ExtraSids-golden
pair naturally with the legacy-DC matrix — build them *with* the 2008 R2 box so they ship proven.
