# ADhammer validation ledger

**This file is the authoritative source of truth for what ADhammer's
current release-line supports.** README, CHANGELOG, PLAN, VECTORS, and
every marketing surface derive from here — not the other way around.
The CI job `validation-ledger` (`scripts/check_validation_ledger.py`)
fails when a public claim exceeds what this ledger records.

## Contract

Every capability in the ledger sits in exactly one status tier:

- **`supported`** — the capability is on the default build, has automated
  unit + integration coverage, AND has a live-validation receipt against
  at least one authorized DC in the current release cycle. This is the
  only tier README is allowed to describe without a qualifier.
- **`experimental`** — the code is behind a Cargo feature that is NOT
  enabled by default. README may mention it only inside a section that
  names the feature flag + calls it experimental. CI still runs
  fmt/clippy/build/test on the feature; live validation is not required.
- **`offline-only`** — the code path exists and is exercised by local
  tests, but has never been proven against a live target in the current
  release cycle. README may reference it only with an explicit "offline
  preflight / wire dry-run" qualifier.
- **`validation owed`** — the code path exists but neither offline nor
  live proof is on file. README MUST NOT reference the capability
  without a "not yet validated" qualifier. `auto`-mode and interactive
  flows MUST NOT present findings from these paths as validated.

Every row below records:

- **Capability** — the operator-facing verb name or documentation-name
  (`attack esc1`, `attack relay --target adcs-http`, `check adcs`).
- **Tier** — one of the four above.
- **Evidence** — where the proof lives (test path, live-validation
  receipt path, or the negative statement "code only").
- **Windows matrix** — which DCs the live-validation was against.
- **Owed** — what still needs to land to move to a higher tier.

## Ledger — v1.4.8 (published) + 1.4.9-local

### Scan + report (default build)

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `adhammer scan` — collector → graph → checks → report | supported | crates/collector + graph + checks + report unit tests; live-validated 2026-08-30 vs Server 2025 | 2025 | 2019 + 2022 receipt |
| HTML report render + sanitize_svg XSS defence | supported | crates/report tests + 5 sanitize KAT tests | n/a | — |
| BloodHound CE v5 ingest bundle | supported | crates/bloodhound unit tests | n/a | ingest into live BloodHound CE v5 receipt |
| JSON report envelope | supported | crates/report unit tests | n/a | — |
| Control-path graph (Tier-0 shortest-cost paths) | supported | crates/graph unit tests + P-DcsyncPath live-validated finding on Server 2025 | 2025 | — |
| Report fingerprint sha256 footer | supported | crates/report unit tests | n/a | — |

### Enum (recon, read-only)

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `enum samr` — SAMR user enumeration | supported | crates/kerberos + dcerpc unit tests + live-validated 2026-08-30 vs Server 2025 | 2025 | 2019 + 2022 receipt |
| `enum lsa` — LSAT name→SID | supported | dcerpc/lsat unit tests + live | 2025 | — |
| `enum net` — network sweep, deep-check subset | supported | cli/enums unit tests + manual verification | 2025 | — |
| `enum dns` — ADIDNS record enumeration | supported | live | 2025 | — |
| `enum adcs` — MS-CRTD template enumeration | supported | ms-crtd unit tests + live | 2025 | — |
| `enum esc` — ESC1-15 registry probe via MS-RRP | supported | live | 2025 | — |
| `enum posture` — DC posture: LDAP-signing, StrongCertBindingEnforce | supported | live | 2025 | — |
| `enum sessions` — SRVSVC sessions enumeration | supported | live | 2025 | — |
| `enum krb-users` (WS-KERBRUTE) | supported | 27 tests in adhammer-kerberos + live 2026-08-30 vs Server 2025 | 2025 | 2019 + 2022 receipt |
| `enum wkssvc` — WKSSVC logged-on-users | supported | live | 2025 | — |
| `enum hku` — HKU registry walk | supported | live | 2025 | — |

### Kerberos attack surface (default build)

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack roast` (AS-REP + Kerberoast) | supported | 27 tests + live-validated on 2025 | 2025 | 2019 + 2022 receipt |
| `attack spray` (Kerberos password spray) | supported | live | 2025 | 2019 + 2022 |
| `attack asktgt` — password/hash → TGT ccache | supported | live | 2025 | 2019 + 2022 |
| `attack ptt` — pass-the-ticket (formerly `pth`) | supported | live 2025 SYSTEM RCE | 2025 | 2019 + 2022 |
| `attack rbcd` — S4U2Self + S4U2Proxy | supported | live | 2025 | 2019 + 2022 |
| `attack constrained` — constrained delegation abuse | supported | live | 2025 | 2019 + 2022 |
| `attack unconstrained` (WS-DELEGATION-CAPTURE partial) | offline-only | LDAP recon test | n/a | full listener + AP-REQ capture — 1.5.0 |
| `attack golden` (WS-GOLDEN-TICKET) | supported | live 2025 KB5020805 KDC accept | 2025 | 2019 + 2022 receipt |
| `attack silver` | supported | live | 2025 | 2019 + 2022 |
| `attack diamond` (WS-DIAMOND-TICKET) | supported | 27 tests inc. cname-inheritance + live | 2025 | 2019 + 2022 |
| `attack unpac` (WS-UNPAC-PKINIT) | supported | live 2026-08-30 vs 2025 | 2025 | 2019 + 2022 |

### DCSync + replication

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack dcsync` single-object (DRSUAPI EXOP_REPL_OBJ) | supported | live | 2025 | 2019 + 2022 |
| `attack dcshadow --prep` (LDAP path, ≤ 2016) | offline-only | live-negative-validated on 2019+ ("system-owned attr" block) | 2016 negative | 2016 positive receipt |
| `attack dcshadow --drsuapi --prep` (WS-2, 2019+) | supported | live 2025 | 2025 | 2019 + 2022 |
| `attack dcshadow --drsuapi --push` (WS-DCSHADOW-DRSR) | validation owed | code path exists | — | benign-attribute end-to-end receipt |
| `attack cleanup` (rollback of dcshadow prep) | supported | idempotence test + live | 2025 | — |

### Coerce + relay chain

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack coerce` — PetitPotam (MS-EFSR) | supported | live | 2025 | 2019 + 2022 |
| `attack coerce` — PrinterBug (MS-RPRN) | supported | live | 2025 | 2019 + 2022 |
| `attack coerce` — DFSCoerce (MS-DFSNM) | supported | live | 2025 | 2019 + 2022 |
| `attack coerce` — ShadowyCoerce (MS-FSRVP) | supported | live | 2025 | 2019 + 2022 |
| `attack capture` — NetNTLMv2 SMB listener | supported | live | 2025 | 2019 + 2022 |
| `attack poison` — LLMNR/NBT-NS lure (WS-LLMNR-POISON) | supported | live | 2025 | 2019 + 2022 |
| `attack relay --target ldap-keycred` (shadow creds) | supported | live | 2025 | 2019 + 2022 |
| `attack relay --target rbcd` | supported | live | 2025 | 2019 + 2022 |
| `attack relay --target adcs-http` (WS-ESC8-END-TO-END) | validation owed | handler exists; adcs_relay module tested offline | — | end-to-end CA cert issued from relay receipt |
| `attack relay --target icpr` (ESC11) | validation owed | handler exists; wire complete | — | live CA policy-permitting receipt |

### AD CS / ADCS

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `check adcs` — ESC1-15 static analysis (ms-crtd) | supported | ms-crtd rule pack unit tests + live enumeration | 2025 | — |
| `attack esc1` (WS-ESC1-EXPLOIT) | supported | 6-stage checklist + live on lab CA | 2025 lab CA | 2019 + 2022 |
| `attack esc4` — template DACL abuse | supported | live | 2025 | 2019 + 2022 |
| `attack icpr-esc1` — MS-ICPR CSR marshaled | offline-only | ms-icpr unit tests + offline preflight; wire complete | — | live submission receipt (WS-ESC3-CHAIN partial) |
| `attack shadowcred` — msDS-KeyCredentialLink write + PKINIT | supported | live | 2025 | 2019 + 2022 |

### Lateral movement (post-auth RCE)

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack exec` (WS-PSEXEC — SVCCTL LocalSystem) | supported | live 2025 SYSTEM RCE | 2025 | 2019 + 2022 |
| `attack atexec` (WS-ATEXEC — MS-TSCH task) | supported | live 2025 | 2025 | 2019 + 2022 |
| `attack wmiexec` (WS-WMIEXEC — DCOM Win32_Process.Create) | supported | live 2025 (unblocked from SEALED in 1.4.8) | 2025 | 2019 + 2022 |
| `attack winrm` (WS-EVIL-WINRM — WS-Man 5985) | supported | live | 2025 | 2019 + 2022 |
| `attack secretsdump` (WS-SAM-SECURITY-DUMP) | supported | live via RRP + reg-save fallback | 2025 | 2019 + 2022 |

### LDAP write / abuse

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack abuse --action add-spn` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action add-member` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action set-password` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action add-keycred` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action write-rbcd` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action write-owner` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action write-dacl` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action set-primary-group` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action gpo-link-modify` | supported | live | 2025 | 2019 + 2022 |
| `attack abuse --action allowed-to-act` | supported | live | 2025 | 2019 + 2022 |
| `--dry-run` on every abuse action | supported | unit + live | 2025 | — |
| `attack dns` — ADIDNS record write | supported | live | 2025 | 2019 + 2022 |

### Secrets

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack gmsa` — msDS-ManagedPassword read | supported | live | 2025 | 2019 + 2022 |
| `attack laps` — ms-Mcs-AdmPwd (legacy) | supported | live | 2025 | 2019 + 2022 |
| `attack laps` — msLAPS-Password (Windows LAPS, unencrypted) | supported | live | 2025 | 2019 + 2022 |
| `attack laps` — msLAPS-EncryptedPassword via `dpapi-ng` | supported | live where GKDI rights available | 2025 | 2019 + 2022 |
| `attack lsa` — LSA secrets dump via RRP | supported | live | 2025 | 2019 + 2022 |
| `attack samr` — SAMR user enum via RPC | supported | live | 2025 | 2019 + 2022 |
| `attack dpapi-master-key` (WS-DPAPI-MASTER-KEY) | supported | byte-oracle vs impacket 0.14 + live 2025 | 2025 | 2019 + 2022 |
| DPAPI blob decrypt chain | offline-only | round-trip KAT in dpapi-offline 0.1.3-dev | n/a | byte-oracle vs impacket for blob; live receipt |

### Sysvol / GPO

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `scan --sysvol` — GPP cpassword (MS14-025) | supported | crates/sysvol unit + fuzz + live | 2025 | 2019 + 2022 |
| GptTmpl.inf policy analysis | supported | crates/sysvol unit + fuzz | n/a | — |

### Server-2025-specific

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack badsuccessor` (dMSA succession, Server 2025) | supported | live 2025 | 2025 only | n/a — not applicable pre-2025 |
| `attack zerologon` — CVE-2020-1472 SAFE detect | supported | live-negative-validated on patched 2025 | patched-2025 | ≤ 2020 unpatched positive receipt |

### Auxiliary

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| `attack mssql` (WS-1) — TDS 7.4 xp_cmdshell | offline-only | opt-in `mssql` feature; TDS parse unit tests | — | live SQL Server + xp_cmdshell receipt |
| `attack mssql --execute-as` chain | offline-only | opt-in feature; unit tests | — | live receipt |
| `dump laps` — bulk LAPS read | supported | live | 2025 | 2019 + 2022 |
| `dump gmsa` — bulk gMSA read | supported | live | 2025 | 2019 + 2022 |

### Interactive / auto

| Capability | Tier | Evidence | Windows | Owed |
|---|---|---|---|---|
| interactive TUI (`adhammer` bare) | supported | live-manual per release | n/a | — |
| `auto` — supported-finding validators only | supported | each auto path derives from a supported ledger row | 2025 | 2019 + 2022 |
| `auto` presents unsupported findings as "potential" not "validated" | supported | policy in cli/src/attacks/auto.rs | n/a | — |

### Experimental (opt-in feature flags)

| Capability | Tier | Evidence | Feature flag | Owed |
|---|---|---|---|---|
| collector `ms-gkdi` direct adapter (not via `dpapi-ng`) | experimental | code only; upstream ms-gkdi lacks KATs | `experimental-gkdi` | Windows-generated KATs → move to `supported` OR delete |
| `tls-native` TLS backend (OpenSSL/Schannel) | supported | cargo check under feature; live for legacy DC SHA-1 | `tls-native` | — |
| GSSAPI auth (Linux/macOS) | supported | cargo check under feature | `gssapi` | — |

## Deprecated / retired

| Capability | Retired in | Reason |
|---|---|---|
| `check krb-seal` + `AesCts96Sealer` + `rpc_seal` | 1.4.8 (commit 3801471) | WS-4-P2 SEALED-BLOCKED; kept git history at v1.4.7 for the day it comes back |
| WS-SKELETON-KEY (never shipped) | 1.4.8 plan-cut | Duplicates WS-GOLDEN-TICKET persistence; per-Windows-version binary shim |
| `pac_parse_full` fuzz target | 1.4.9 (commit 8296ba2) | Directly hit picky-krb 0.9.6's AES-CTS internal-panic surface; coverage retained via `pac_credential_info` outer path |

## How to add a row

1. Land the code.
2. If the code path takes attacker-controllable input, add a fuzz target
   (see `fuzz/fuzz_targets/`).
3. Add unit + integration tests.
4. Add a row here with tier = `offline-only` initially.
5. Run against the live lab; save the receipt path.
6. Promote to `supported`.
7. Update README to reference the capability (CI job will fail if you
   reference it before the row exists).

## How to demote a row

If a live-validation receipt goes stale (Windows patched a bug the row
depended on, Microsoft changed a protocol, etc), demote the row to
`validation owed` in the same commit that discovered the drift.
Publishing a new release with a stale receipt is a leak of trust.

## The CI enforcement gate

`scripts/check_validation_ledger.py` runs on every push. Reads every row
from this file + greps `README.md`, `CHANGELOG.md`, and `docs/PLAN_*.md`
for feature-name references. Fails when any of:

- A public claim exists that maps to no ledger row.
- A row is marked `validation owed` but a public claim describes it as
  supported / validated / live.
- A row references a Windows version not in the current release-cycle
  matrix and no negative-validation receipt exists.

Exit code 0 → green. Exit code 1 → CI red. The script is intentionally
strict — pushing the line "we support X" without a ledger row is a bug
class we're not going to keep having.
