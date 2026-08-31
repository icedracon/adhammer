# ADhammer threat model

Written for a security reviewer deciding whether to trust the tool inside
an authorized-engagement workflow. Covers the tool's own attack surface,
not the AD attacks it performs. Pair with `SECURITY.md` for the
disclosure policy.

## System model

```
                                            +---------------------+
   +--------------+                          |                     |
   |   Operator   |    ssh / RDP / local     |  Operator's box     |
   |   (human)    | -------------------------->  (Kali / Windows / |
   |              |                          |   macOS engagement) |
   +--------------+                          |                     |
                                             |  adhammer CLI        |
                                             |  ~/.config/adhammer/ |
                                             |   session.json       |
                                             |  ~/.cache/adhammer/  |
                                             |   *.ccache, *.kirbi  |
                                             +----------+----------+
                                                        |
                                                        | LDAP(S) 389/636
                                                        | Kerberos    88
                                                        | SMB2       445
                                                        | RPC/EPM    135
                                                        | WinRM     5985
                                                        | HTTP(S)  ADCS
                                                        v
                                                +----------------+
                                                | Target domain  |
                                                | Windows DC(s)  |
                                                | ADCS host      |
                                                | Member servers |
                                                +----------------+
```

## Assets

| Asset | Where it lives | Confidentiality | Integrity |
|---|---|---|---|
| Operator's AD credentials (password, NT hash, cert, ccache) | operator box: RAM, `~/.config/adhammer/session.json` (DPAPI-sealed on Windows), `~/.cache/adhammer/*.ccache` | Critical | Critical |
| Captured target credentials (dcsync output, unpac NT hash, DPAPI master key, hive dumps) | operator box: RAM, operator-chosen output files, HTML report | Critical | Critical |
| Wire captures (AS-REP, TGS-REP, DPAPI blobs) | operator box: RAM, optional `--trace-out` files | High | Medium |
| Scan output (LDAP dump, findings, graph) | operator box: JSON/HTML report | Medium | High |
| Target DC state (never modified by scan, mutated by `attack abuse` / `dns` / `dcshadow`) | target DC | (target's asset) | (target's asset) |

## Actors and their capabilities

### 1. The operator (trusted)

- Runs the tool. Owns the operator box.
- Provides credentials via CLI args, env vars, or the interactive
  session's DPAPI-sealed store.
- **Not modeled as an adversary.** Anything the operator can do on their
  own box is outside the threat model.

### 2. The target domain administrator (semi-trusted for detection)

- Sees ADhammer's LDAP queries, Kerberos AS-REQ patterns, SMB2 tree-
  connects, WinRM sessions, ADCS enrollments.
- Can trigger detections in a SIEM. That's expected; ADhammer is not a
  stealth tool.
- **Cannot** reach back into the operator box unless the operator
  connects to a hostile share / cert / etc. — see actor 3.

### 3. A hostile / compromised target endpoint (adversary)

- Speaks to us over LDAP / Kerberos / SMB2 / RPC / HTTP(S) as a
  responder.
- May be a real Windows DC that turned malicious mid-engagement, a
  Samba honeypot, or a random TCP-listener on port 88 the operator
  aimed the tool at by mistake.
- **Attack surface:** every parser that decodes bytes off the wire.
  - Kerberos AS-REP / TGS-REP / PAC (`adhammer-kerberos::pac`,
    `::pkinit`, `::tgs`).
  - NDR unmarshaller (`dcerpc::ndr`).
  - SMB2 response parsing (`smb2-client`).
  - LDAP result entries (`adhammer-collector::to_object` +
    `ldap3::SearchEntry`).
  - HTTPS response bodies (`adcs_relay`, `winrm`).
  - DPAPI blob parser (`dpapi-offline::blob`).
- **Defences today:** per-read deadlines on Kerberos / LDAP / WinRM /
  ADCS (1.4.8 audit), bounds-checked slice reads in
  `adhammer-kerberos::unpac`, `Redacted<T>` at all secret sites.
- **Defences missing:** fuzz targets for the parsers above (WS-FUZZ-6 in
  1.4.9), NDR64 not implemented.

### 4. A local attacker on the operator's box (adversary)

- Same OS user as the operator (no privilege escalation assumed).
- Can read the operator's own files, environment variables, process
  memory (via `/proc/<pid>/mem` on Linux, `ReadProcessMemory` on
  Windows).
- **Attack surface:** everything the operator can access. This actor is
  already game-over for the credentials the operator holds; we don't
  try to defend against them.
- **Small mitigations:** session.json DPAPI-sealed on Windows;
  Redacted<T> keeps hashes out of debug output; env-var secret input
  keeps values out of `ps` / shell history.
- **Not a mitigation:** any encryption-at-rest of ccache / kirbi / hive
  dumps. Those are operator-chosen output paths; owner is the operator.

### 5. A downstream consumer of the operator's report / SBOM (semi-trusted)

- Reads HTML report, JSON output, BloodHound-CE ingest bundle, SBOM.
- **Cannot** be given arbitrary bytes to execute — the HTML report went
  through `sanitize_svg()` in 1.4.8, HTML entities are escaped at
  render, and the JSON is well-formed.
- **Attack surface:** any XSS bypass in the report renderer, any file-
  path that traverses.

## Trust boundaries

1. **Wire → parser.** Every byte reaching our parsers is attacker-
   controllable (actor 3). Defences: bounds-checks, per-read timeouts,
   fuzzing (WS-FUZZ-6).
2. **Parser → in-memory model.** Once bytes are in an
   `adhammer-core::Object` (LDAP) or `Tgt` (Kerberos), they're trusted
   for the rest of the pipeline. Defences: Redacted<T> for secret
   fields.
3. **In-memory model → report.** HTML rendering escapes all string
   fields, SVG passes through `sanitize_svg`. Defences:
   sanitize + escape.
4. **In-memory model → wire (outbound).** LDAP writes, ADCS enrollments,
   RPC calls emitted by attack modules. Defences: `--dry-run` on every
   `attack abuse` write; explicit `y/N` prompts on destructive ops in
   interactive mode.
5. **Operator credential → wire.** Kerberos AS-REQ, LDAP bind, SMB
   session-setup, WinRM auth. Defences: sealed bind wherever the DC
   accepts it; NTLM MIC computed; Kerberos etype negotiated per KDC.

## Non-goals

ADhammer is **not**:

- A defensive tool. It does not detect its own execution; SOC integration
  is not designed for.
- A stealth framework. Every attack verb generates the exact wire it
  would generate in a normal Windows operation; no evasion is layered
  in.
- A persistence framework. Golden / Diamond / SidHistory tickets are
  forgeable, not persistable — the operator gets a ccache, not a
  service-installed backdoor.
- An Azure / Entra ID / M365 tool. Permanent no. Different auth model,
  different tool.
- A password cracker. `--userlist` files and Kerberos-derived hashes go
  to hashcat / john externally.
- A malware framework. Attack modules refuse to write persistent files
  outside the operator's own `~/.cache/adhammer/`.

## Explicit accepted risks

- **`rsa 0.9.x` Marvin sidechannel.** Practical impact zero in
  ADhammer's short-burst usage. If usage shape changes to long-lived
  decryption oracle, revisit. `.cargo/audit.toml` documents.
- **Credentials in `session.json`** are DPAPI-sealed on Windows only.
  On Linux / macOS the file is plaintext under 0600 in the operator's
  own home. Documented in `--help --old`.
- **RC4-HMAC (etype 23)** ships behind `--rc4` for legacy-DC compat.
  Not enabled by default in any 1.4.x verb.

## Threat model change log

- **2026-08-31 (1.4.9-plan)** — first version.
