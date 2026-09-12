# ADhammer 1.5.1 — Method Catalog (W151-01, P0)

**Status:** inventory of the dispatch surface as-of worktree at 2026-09-11.
Not a live-evidence certificate. Baseline commit: `87ac44be` **plus dirty tree
+ untracked implementation files** (4 attack modules, typed_json, gap_hint,
new docs/GAPS.md). This catalog is the reference set that W151-02 → W151-06
must align to; each row also carries the *review depth* actually attempted.

Review-depth ladder (per PLAN_1.5.1.md §W151-01):

- `I` inventory — CLI/menu/help line traced to a handler ID.
- `B` boundary — argument surface + preflight + failure classes checked.
- `K` backend — the crate/protocol call chain that actually runs.
- `L` local-test — synthetic / offline test around the boundary or backend.
- `E` live-evidence — validated end-to-end against a real target this cycle.

Nothing in this document promotes anything to `L` or `E` in the ledger.

Legend for `Effect`: **R** read-only · **W** state-changing · **N** network
listener/sender that receives victim traffic · **X** local file write only
(offline / decode / dump-parse).

Legend for `Menu`: ✓ = wired into the interactive two-level menu; ✗ = CLI-only
(not reachable from the interactive front door — drift, see §Drift).

## 1. Top-level verb tree

Source: `cli/src/main.rs` `enum Command` (line 118).

| ID | CLI form | Handler dispatch | Group / subcommand count | Notes |
|---|---|---|---|---|
| V-scan     | `adhammer scan …`     | `attacks::scan::run`                 | flat (ScanArgs) | Passive audit → graph → checks → report. |
| V-enum     | `adhammer enum <sub>`  | `EnumCmd` (18 variants)              | subgroup | Read-only enumeration. |
| V-attack   | `adhammer attack <sub>`| `AttackCmd` (30 variants)            | subgroup | Active attacks. |
| V-kerb     | `adhammer kerb <sub>`  | `attacks::kerb::KerbCmd` (4 variants)| subgroup | Direct Kerberos primitives (F1a/F1c/F3). |
| V-creds    | `adhammer creds <sub>` | `attacks::creds::CredsCmd` (1 var.)  | subgroup | Offline decode / recovery (F6; F4a/b pending). |
| V-ldap     | `adhammer ldap <sub>`  | `attacks::ldap::LdapCmd` (1 var.)    | subgroup | Direct LDAP primitives (F1b). |
| V-lsa      | `adhammer lsa <sub>`   | `attacks::lsa_offline::LsaCmd` (1 v.)| subgroup | Offline LSASS decode (F5 scaffold). |
| V-check    | `adhammer check <sub>` | `CheckCmd` (1 variant)               | subgroup | Single-taxonomy check runners. |
| V-auto     | `adhammer auto …`      | `AutoArgs` → guided pipeline         | flat | Scan → validate → PoC → report bundle. |
| V-setup    | `adhammer setup <sub>` | `setup::SetupCmd` (1 variant)        | subgroup | Onboarding helpers (krb5.conf writer). |
| V-run      | `adhammer run …`       | `blackbox::run`                      | flat | No-cred black-box DC discovery (SRV + fingerprint). |
| V-doctor   | `adhammer doctor …`    | `doctor::run`                        | flat | Preflight (DNS SRV + TCP matrix + classified bind). |
| V-completions | `adhammer completions <shell>` | clap_complete emit          | flat | bash/zsh/fish/powershell/elvish. |
| V-man      | `adhammer man`         | roff render                          | flat | Emits `adhammer.1` to stdout. |
| V-gaps     | `adhammer gaps`        | GAPS.md digest                       | flat | External-tool swap-in list. |

**Interactive front door** (`adhammer` with no args) drops into
`interactive::main_loop` → 5-category grouped menu (Recon / Creds / Lateral /
Persist / Session). See `enum Action` in `cli/src/interactive.rs:50` — **57
variants**, mapped from menu labels in `CATEGORIES` (line 107). The menu
does *not* cover every CLI subaction; see §5 Drift.

## 2. Enum subcommand catalog — `adhammer enum <sub>`

Source: `cli/src/main.rs:229` `enum EnumCmd`. Handler symbols cited at the
concrete `attacks::*` / `enums::*` module.

| ID | CLI | Menu Action | Backend | Auth | Effect | Depth | Notes / gaps |
|---|---|---|---|---|---|---|---|
| E-samr        | `enum samr`     | `EnumSamr`    | `attacks::samr` — SAMR over SMB pipe    | domain-creds | R | I,B | |
| E-lsa         | `enum lsa`      | `EnumLsa`     | `attacks::lsa` — LSAT `\lsarpc`         | domain-creds | R | I,B | |
| E-net         | `enum net`      | `NetSweep`    | `enums::net` — hand-rolled TCP sweep + SMB signing probe | none | R | I,B | Largest module (1145 LOC). |
| E-dns         | `enum dns`      | `DnsEnum`     | `enums::dns` — LDAP `MicrosoftDNS` scan | domain-creds | R | I,B | adidnsdump shape. |
| E-adcs        | `enum adcs`     | `AdcsEnum`    | `enums::dns` (typed alias)              | domain-creds | R | **I only** | **DRIFT** — `EnumCmd::Adcs(enums::dns::DnsArgs)` reuses DnsArgs. Either a stub or arg-sharing shortcut. Must confirm the handler actually branches to CA-probe code, not DNS enumeration. |
| E-esc         | `enum esc`      | `EnumEsc`     | `enums::esc_registry` — MS-RRP ESC 6/10/11/16 | domain-creds | R | I,B | Needs Remote Registry service. |
| E-posture     | `enum posture`  | `EnumPosture` | `enums::posture` — LDAP-signing / CB / Spooler | domain-creds | R | I,B | |
| E-sessions    | `enum sessions` | `EnumSessions`| `enums::sessions` — SRVSVC NetrSessionEnum | domain-creds | R | I,B | |
| E-wkssvc      | `enum wkssvc`   | *(none)* ✗    | `enums::sessions` (level 1)             | local-admin | R | I | **DRIFT** — not in menu. |
| E-hku         | `enum hku`      | *(none)* ✗    | `enums::sessions` — HKU walk via MS-RRP | often no-admin | R | I | **DRIFT** — not in menu. |
| E-sccm        | `enum sccm`     | `EnumSccm`    | `enums::sccm` — `CN=System Management`  | domain-creds | R | I | |
| E-scom        | `enum scom`     | `EnumScom`    | `enums::sccm` (same Args, different container) | domain-creds | R | I | Shared type — document why. |
| E-krb-users   | `enum krb-users`| *(none)* ✗    | `enums::krb` — pre-auth-less AS-REQ     | **none** | R | I,B | Kerbrute-shape. **DRIFT** — not in menu. |
| E-web         | `enum web`      | *(none)* ✗    | `enums::web` — HTTP(S) AD-surface fp    | **none** | R | I,B | 1.5.0 WS-WEB-FP. **DRIFT** — not in menu. |
| E-nullbind    | `enum nullbind` | *(none)* ✗    | `enums::nullbind` — null-session SAMR   | **none** | R | I,B | 1.5.0. **DRIFT** — not in menu. |
| E-rpc-null    | `enum rpc-null` | *(none)* ✗    | `enums::rpcnull` — anon SRVSVC+WKS+LSA  | **none** | R | I,B | 1.5.0. **DRIFT** — not in menu. |
| E-shares      | `enum shares`   | *(none)* ✗    | `enums::shares` — anon NetrShareEnum L1 | **none** | R | I,B | 1.5.0. **DRIFT** — not in menu. |
| E-host        | `enum host`     | *(none)* ✗    | `enums::host` — unified anon sweep      | **none** | R | I,B | 1.5.0 WS-BB-HOST. **DRIFT** — not in menu. |
| E-sysvol      | `enum sysvol`   | *(none)* ✗    | `enums::sysvol` — anon SYSVOL GPP walk  | **none** | R | I,B | 1.5.0 WS-SYSVOL-ANON. **DRIFT** — not in menu. |

## 3. Attack subcommand catalog — `adhammer attack <sub>`

Source: `cli/src/main.rs:302` `enum AttackCmd`.

| ID | CLI | Menu Action | Backend | Effect | Depth | Notes |
|---|---|---|---|---|---|---|
| A-roast          | `attack roast`         | `Roast`         | `attacks::scan` roast path | R | I,B | Kerberoast + AS-REP roast. |
| A-spray          | `attack spray`         | `Spray`         | `attacks::spray` | R | I,B | |
| A-abuse          | `attack abuse`         | `Abuse`         | `attacks::abuse` | **W** | I,B | **Preview by default**, requires `--commit`. |
| A-coerce         | `attack coerce`        | `Coerce`        | `attacks::coerce` | W | I,B | PetitPotam / MS-EFSR. |
| A-zerologon      | `attack zerologon`     | `Zerologon`     | `attacks::zerologon` | R | I,B | Safe detection only — never resets. |
| A-rbcd           | `attack rbcd`          | `Rbcd`          | `attacks::rbcd` (S4U2Self+S4U2Proxy) | W | I,B | |
| A-constrained    | `attack constrained`   | `Constrained`   | `attacks::rbcd` (shared) | W | I,B | Shared type — different path. |
| A-asktgt         | `attack asktgt`        | `Asktgt`        | `attacks::asktgt` | X | I,B | Writes ccache. |
| A-dcsync         | `attack dcsync`        | `Dcsync`        | `attacks::dcsync` (DRSUAPI) | R | I,B | Sealed RPC. |
| A-capture        | `attack capture`       | `Capture`       | in-crate SMB listener | **N** | I,B | Requires privileged port for 445. |
| A-poison         | `attack poison`        | `Poison`        | LLMNR/NBT-NS spoof | **N** | I,B | |
| A-relay          | `attack relay`         | `Relay`         | `attacks::relay` | N+W | I,B | SMB → LDAP/RBCD/AD CS Web/ICPR. |
| A-exec           | `attack exec`          | `Exec`          | `attacks::exec_pack` (SVCCTL) | W | I,B | psexec-style. |
| A-atexec         | `attack atexec`        | *(none)* ✗       | `attacks::exec_pack` (TSCH) | W | I | **DRIFT** — not in menu. |
| A-wmiexec        | `attack wmiexec`       | `Wmiexec`       | `attacks::exec_pack` (WMI DCOM) | W | I,B | |
| A-secretsdump    | `attack secretsdump`   | `Secretsdump`   | `attacks::secretsdump` | R+X | I,B | Local reg save → C$. |
| A-gmsa           | `attack gmsa`          | `Gmsa`          | `attacks::gmsa` | R | I,B | LDAP read. |
| A-laps           | `attack laps`          | `Laps`          | `attacks::laps` | R | I,B | Both ms-Mcs-AdmPwd + msLAPS-Password. |
| A-winrm          | `attack winrm`         | `Winrm`         | `attacks::winrm_exec` | W | I,B | 5985/HTTP + msg encryption. |
| A-esc1           | `attack esc1`          | `Esc1`          | `attacks::esc1` | W | I,B | Enroll with spoofed UPN SAN. |
| A-icpr-esc1      | `attack icpr-esc1`     | *(none)* ✗       | `attacks::icpr_esc1` | W | I | Sealed pipe **not wired** — offline preflight only. **DRIFT** — not in menu. |
| A-golden         | `attack golden`        | `Golden`        | `attacks::golden` | X | I,B | Krbtgt AES256 forge. |
| A-diamond        | `attack diamond`       | *(none)* ✗       | `attacks::diamond` | X | I | 1.4.8-A. **DRIFT** — not in menu. |
| A-unpac          | `attack unpac`         | *(none)* ✗       | `attacks::unpac` | R | I | **Aliased via `kerb u2u-nt` menu row.** Consider promoting `attack unpac` to menu or removing the duplication. |
| A-dpapi-mk       | `attack dpapi-master-key` | *(none)* ✗    | `attacks::dpapi_mk` | R | I | 1.4.8-B. **DRIFT** — not in menu. |
| A-silver         | `attack silver`        | `Silver`        | `attacks::silver` | X | I,B | Service-key TGS forge. |
| A-ptt (pth)      | `attack ptt` (alias `pth`) | `Pth`        | `attacks::ptt` | W | I,B | Menu row labeled "Pass-the-ticket". CLI has deprecation warning. |
| A-unconstrained  | `attack unconstrained` | `Unconstrained` | `attacks::scan` (delegation-filter path) | R | I,B | |
| A-badsuccessor   | `attack badsuccessor`  | `Badsuccessor`  | `attacks::badsuccessor` | W | I,B | Server 2025 dMSA path. |
| A-esc4           | `attack esc4`          | `Esc4`          | `attacks::esc4` | W | I,B | Preview by default per F-C2 (commit `fd15388`). |
| A-shadowcred     | `attack shadowcred`    | `Shadowcred`    | `attacks::shadowcred` | W | I,B | Thin alias over `abuse --add-keycred` + `pkinit`. |
| A-dcshadow       | `attack dcshadow`      | `Dcshadow`      | `dcshadow.rs` | W | I,B | LDAP path dead ≤2016; `--drsuapi` path for 2019+. |
| A-mssql          | `attack mssql`         | `Mssql`         | `attacks::mssql` (feature `mssql`) | W | I,B | TDS 7.4 over NTLM. |
| A-dns (write)    | `attack dns`           | `AttackDns`     | `attacks::dns` — ADIDNS record write | W | I,B | Dry-run default. |

## 4. Other groups

### `adhammer kerb …` (V-kerb, new in 1.5.1)

| ID | CLI | Menu Action | Depth | Notes |
|---|---|---|---|---|
| K-pkinit    | `kerb pkinit`     | `KerbPkinit` | I,B | Uses `adhammer_kerberos::pkinit`. Accepts `--pfx` (needs new `p12=0.6` dep — see §Deps) or `--key/--cert`. |
| K-u2u-nt    | `kerb u2u-nt`     | `KerbU2uNt`  | I | Type-aliased to `attacks::unpac::UnpacArgs`. |
| K-trust-mint| `kerb trust-mint` | *(none)* ✗    | I | Thin wrapper over `attack asktgt` with `$`-suffix. **DRIFT.** |
| K-trust-dump| `kerb trust-dump` | *(none)* ✗    | I | Blocks on `ms-lsad v0.3` — `LsarRetrievePrivateData`. **DRIFT.** |

### `adhammer creds …` (V-creds, new in 1.5.1)

| ID | CLI | Menu Action | Depth | Notes |
|---|---|---|---|---|
| C-gpp-decrypt | `creds gpp-decrypt` | `GppDecrypt` | I,B | `adhammer_sysvol::gpp::decrypt_cpassword`. Positional or `--file`. |

### `adhammer ldap …` (V-ldap, new in 1.5.1)

| ID | CLI | Menu Action | Depth | Notes |
|---|---|---|---|---|
| L-auth      | `ldap auth` | *(none)* ✗ | I,B | Own tokio-rustls TLS stack (ldap3 lacks client-cert setter). **Bind test only** — result not shared with collector's session store. **DRIFT.** |

### `adhammer lsa …` (V-lsa, new in 1.5.1)

| ID | CLI | Menu Action | Depth | Notes |
|---|---|---|---|---|
| Y-lsass-parse | `lsa lsass-parse` | *(none)* ✗ | I | **Scaffold only** — outer MDMP directory reader; per-build symbol walk deferred. Emits `[hint]` at gap sites. **DRIFT.** |

### `adhammer check …`

| ID | CLI | Menu Action | Depth | Notes |
|---|---|---|---|---|
| CK-adcs     | `check adcs` | *(none)* ✗ | I,B | `ms-crtd::detect_esc` ESC1-15 rule pack over pKICertificateTemplate. **DRIFT — not in menu.** |

### `adhammer setup …`

| ID | CLI | Menu Action | Depth | Notes |
|---|---|---|---|---|
| S-krb5      | `setup krb5` | *(none)* ✗ | I | Emits working `krb5.conf`. Auto-SRV lookup. |

### Standalone verbs

| ID | CLI | Menu | Depth | Notes |
|---|---|---|---|---|
| V-run       | `run …`         | `recon_wizard` covers no-cred path | I,B | Hand-rolled DNS SRV + DC discovery. |
| V-doctor    | `doctor …`      | *(none)* ✗          | I,B | Preflight; `--json` for scripting. **DRIFT — not in menu.** |
| V-auto      | `auto …`        | `Guided` menu row   | I,B | Scan → validate → PoC bundle. |
| V-scan      | `scan …`        | `Scan` menu row     | I,B | Passive audit + graph + checks. |
| V-completions | `completions <shell>` | n/a           | I | clap_complete. |
| V-man       | `man`           | n/a                 | I | roff to stdout. |
| V-gaps      | `gaps`          | n/a                 | I | `docs/GAPS.md#anchor` digest. |

## 5. Drift — CLI/menu/help disagreements

`enum Action` (interactive) has **57 variants** covering **26 attacks + 12
enums + 3 direct-Kerberos-or-decode + housekeeping**. Full CLI dispatch
exposes **≈ 68 leaf subcommands** across every group. The delta is **not
noise** — some rows are deliberately CLI-only, others are DRIFT to close.

### D-1 — 1.5.0 no-cred enum family missing from the interactive front door

`enum krb-users`, `enum web`, `enum nullbind`, `enum rpc-null`, `enum shares`,
`enum host`, `enum sysvol` shipped in 1.5.0 with the `adhammer run` recon
lane, but only `run` (recon_wizard) exposes them from the menu — a person
who chooses "Recon" from the front door does not see these individual
verbs. **Verdict:** wiring these into a "No-credential recon" sub-section
of Recon (or exposing them from `recon_wizard` menu output) closes a real
gap. Backlog for W151-05.

### D-2 — 1.5.1 primitive verbs partially menu-integrated

Six new leaf verbs landed as part of the F-series primitives. Menu integration
is uneven:

- ✓ Menu-integrated: `kerb pkinit` (KerbPkinit), `kerb u2u-nt` (KerbU2uNt),
  `creds gpp-decrypt` (GppDecrypt).
- ✗ Not menu-integrated: `kerb trust-mint`, `kerb trust-dump`, `ldap auth`,
  `lsa lsass-parse`.

The unwired four are less "polished user tasks" and more "operator primitives
used inside a chain". Options: (a) add them under Creds/Persist categories,
(b) leave CLI-only and add a Gaps entry, (c) require they graduate first
(esp. `lsa lsass-parse` which is scaffold-only). Recommend (c) for
`lsa lsass-parse` (don't sell scaffolding as a menu feature); (a) for
`ldap auth` and both trust verbs.

### D-3 — Attack verbs that shipped without menu wiring

`attack diamond` (1.4.8-A), `attack unpac`, `attack dpapi-master-key`
(1.4.8-B), `attack atexec`, `attack icpr-esc1`. **Verdict:** must decide per
row — `unpac` is redundant with `kerb u2u-nt` (menu already has it), so
consider removing `Action::KerbU2uNt`'s menu row and using `Action::Unpac`
directly. `diamond`, `dpapi-master-key`, `atexec` should be first-class
menu rows in Creds / Lateral. `icpr-esc1` is offline-preflight-only — leave
CLI-only until sealed pipe lands.

### D-4 — `check adcs` and `doctor` not in the menu

Neither surfaces from the interactive front door. `doctor` runs as part of
banner intro? — no, it is a discrete verb. Both should get a "Session" or
"Diagnostics" category row. Backlog for W151-05.

### D-5 — `EnumCmd::Adcs(enums::dns::DnsArgs)` uses DnsArgs

Type reuse looks accidental. If handler branches correctly, document why.
If handler literally runs DNS-enum code and is wrong, this is a **P0
functional bug**. Must be verified in W151-02 (result contract).

### D-6 — `attack pth` alias

`attack pth` → `attack ptt` (visible alias, deprecation warning). Menu
label still says "Pass-the-ticket" → `Action::Pth`. Consistent enough; note
the deprecation.

## 6. Worktree deltas (not in `87ac44be`) — must reconcile before candidate

The plan snapshot (`87ac44be`) does **not** include these worktree changes,
so they are outside the canonical baseline until reviewed:

### Untracked implementation files

- `cli/src/attacks/kerb.rs`         — `KerbCmd` (F1a/c/F3 shell)
- `cli/src/attacks/creds.rs`        — `CredsCmd` (F6)
- `cli/src/attacks/ldap.rs`         — `LdapCmd` (F1b, own rustls stack)
- `cli/src/attacks/lsa_offline.rs`  — `LsaCmd` (F5 scaffold)
- `cli/src/typed_json.rs`           — first-wave typed JSON emitter
- `cli/src/gap_hint.rs`             — `[hint]` block emitter
- `docs/GAPS.md`                    — external-tool swap-in list
- `scripts/scratchpad-bootstrap.sh` — one-off session helper (probably scratch)

### Modified

- `cli/src/attacks/esc4.rs`  — preview-by-default hardening
- `cli/src/attacks/lsa.rs`   — SID resolution changes
- `cli/src/attacks/mod.rs`   — module wiring
- `cli/src/interactive.rs`   — new Action variants + menu rows
- `cli/src/main.rs`          — new subcommand groups
- `cli/Cargo.toml`           — **adds `p12 = "0.6"` (new dep)**
- `Cargo.lock`               — transitive graph deltas
- `CHANGELOG.md`             — 1.5.1 changelog entry

### Staged for deletion (previous PLAN_*.md purge)

Multiple `docs/PLAN_1.4.*.md`, `docs/PLAN_1.5.0.md`, `docs/PLAN_1.5.1_*.md`,
`docs/PLAN_KERBCORE_INTEGRATION.md`, `docs/PLAN_KRB_CRATE.md`,
`.github/FUNDING.yml`, and several ceremonial SVGs / GIFs / casts. Matches the
"strip internal plan/governance doc refs from public docs" pattern from prior
commits. Reconcile against the "does the shipped candidate need any of these"
question in W151-06.

## 7. Dependency deltas noted for W151-06

`cli/Cargo.toml` adds **`p12 = "0.6"`** (MIT/Apache-2.0, pure-Rust PKCS#12
parser). Rationale in the diff: `kerb pkinit --pfx` (F1a) accepts `.pfx`
directly so operators don't shell out to openssl. Transitively pulls
`hmac`, `md-5`, `pbkdf2`, `des`, `rc2`, `sha1` — RustCrypto lineage,
low-surface, already indirect through other RustCrypto deps in tree.
**Not yet reviewed against**: advisories, license notice list, MSRV impact,
`--all-features` vs `--no-default-features` builds, `cargo deny` config,
supply-chain audit freshness. Formal review is the deliverable of W151-06.

## 8. Counts

- Top-level verbs: **15** (`scan enum attack kerb creds ldap lsa check auto setup run doctor completions man gaps`).
- Subcommand leaves across groups:
  - `enum` = 19
  - `attack` = 30
  - `kerb` = 4
  - `creds` = 1 (F4a/F4b pending → +2 planned)
  - `ldap` = 1
  - `lsa` = 1 (scaffold)
  - `check` = 1
  - `setup` = 1
- Flat verbs (no sub): `scan / auto / run / doctor / completions / man / gaps` = **7**
- **Total invocable leaves in this candidate:** `15 flat/group + 58 sub-leaves = 73` unique
  invocable surfaces (counting each leaf once; excluding `pth` alias which is not a distinct
  surface, and excluding CLI aliases in general).
- Interactive Action variants: **57**.
- Menu categories: **5** (Recon / Creds / Lateral / Persist / Session).
- Menu-to-CLI drift rows enumerated: **20** (§5 D-1 … D-6 breakdown).

## 9. What this catalog is **not**

- It is not a compile check. `cargo build --locked` was run locally and PASSED
  for the `adhammer` bin (per PLAN_1.5.1 §"Локальная проверка"). It does not
  cover `--all-features`, workspace-wide `cargo check`, `cargo test`, clippy,
  fmt or MSRV.
- It is not a live-evidence receipt. No verb in this document is marked `E`.
  Promotion to `E` needs the receipt discipline of §Definition-of-done in
  PLAN_1.5.1.md and the Kali VBox live-test rule.
- It is not a promise about what will be published. Distribution mode
  (GitHub-only vs full ecosystem) is still open per PLAN_1.5.1.md.

## 10. Next-step queue this catalog unlocks

- **W151-02** — every row's `Effect` column drives the result-contract work
  (W findings must never silently claim `completed` if the write half failed).
- **W151-03** — every row's `Auth` and backend column feeds the TLS/proxy/
  timeout/cancel parameter-equivalence tests.
- **W151-04** — E-* rows drive finding attribution + partial-collection
  handling (esp. no false clean-bill on `enum posture` failing MS-RRP).
- **W151-05** — the DRIFT list (§5) is the direct scope for menu unification.
- **W151-06** — §6 worktree deltas + §7 dependency delta are the direct
  scope of the package/release gate.
