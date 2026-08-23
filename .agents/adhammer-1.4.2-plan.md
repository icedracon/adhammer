# adhammer 1.4.2 — the "completion + fortress" release

Follow-on to 1.4.1 (the "grandiozno" WS-1..5 modern-attack pack). 1.4.2 closes the
last three big gaps on-prem AD engagements complain about, and ships proven coverage
on every current-and-legacy Windows Server version.

## Grand narrative (for launch)

Three closing chapters:
1. The classic one-shot CVEs (noPac, Zerologon) — patched everywhere on paper, still
   present on the legacy tiers every real engagement finds.
2. Forest trust chain exploitable end-to-end — trust-key extraction + cross-forest
   golden ticket in a single tool, no hand-off between languages.
3. Validated coverage on every Windows Server (2016 / 2019 / 2022 / 2025), not just 2025.

Tagline: **"The completion release."**

## Scope — 8 workstreams (WS-A..E + WS-F/G/H absorbed from IronEye competitive scan 2026-08-23)

### WS-A — Classic AD CVE pack (noPac + Zerologon)

- **WS-A1** noPac (CVE-2021-42278 + 42287). sAMAccountName rename chain: create a
  computer account (MAQ > 0), clear its SPN, rename `sAMAccountName` → `DC01`
  (no trailing `$`), AS-REQ TGT for `DC01`, rename back → S4U2Self as
  `Administrator` → DCSync-capable service ticket as `DC01$`.
- **WS-A2** Zerologon (CVE-2020-1472). Netlogon AES-CFB8 with all-zero IV: an
  all-zero-plaintext encryption yields zero with ~1/256 probability per attempt;
  after success, `NetrServerPasswordSet2` sets the DC computer account password to
  empty → DCSync.
- **Effort:** M-L (5-6 d).
- **Blocked on:** WS-E (legacy DC required for positive validation; both CVEs are
  patched on lab 2025 and can only be *negatively* validated there).
- **Reuses:** collector LDAP object-create/modify plumbing (also fuels ESC writes),
  netlogon crate AES-CFB8 primitive (already in dcerpc).

### WS-B — Forest-trust attack chain

Trust-key extraction via DRSUAPI (unblocked by 1.4.1 WS-6 bulk `GetNCChanges`) →
inter-realm TGT forge signed with the trust key → DA in the trusted forest.

- Extract inter-realm trust key from `trustedDomain` object's
  `trustAuthIncoming` / `trustAuthOutgoing` via DRSUAPI bulk pull.
- Forge inter-realm TGT (`krbtgt/TRUSTED.LOCAL@TRUSTING.LOCAL` cross-realm
  referral ticket) using the trust key.
- S4U2Self → S4U2Proxy as DA in the trusted forest.
- **Effort:** M (4 d). Pairs naturally with 1.4.1 WS-3 (cross-forest Kerberos).

### WS-C — Wire hardening probes

`scan` gains two defensive-posture detections. Detect only — the probes never send
crafted auth, only reads a bind response and fingerprints it.

- **LDAP channel binding** — bind with an intentionally-invalid Channel-Binding
  Token; server response distinguishes enforced (`STATUS_LOGON_FAILURE` — no CB
  match) vs optional (`STATUS_SUCCESS`).
- **SMB3 encryption** — read negotiate response `Capabilities` +
  `EncryptionCapabilities` context (SMB2 dialect 3.1.1+); flag if encryption is
  optional or absent on servers where it should be required.
- **Effort:** S (2 d).

### WS-D — `krb-listen` crate

Standalone unconstrained-delegation TGT harvester (was task #18). Runs alongside
`attack coerce` on a delegation-enabled host: local SMB2 server accepts the
coerced Kerberos AP-REQ, decrypts the embedded delegated TGT with the delegation
account's key, dumps ccache. Emits both `.ccache` (usable by any Kerberos client)
and JSON (for adhammer to consume via `attack pth`).

- New published crate under `icedracon/krb-listen`.
- **Effort:** M (3 d).

### WS-F — SCCM + SCOM enumeration

Deep-query LDAP walks for System Center Configuration Manager + Operations
Manager objects. Competitive gap surfaced by IronEye (2026-08-23).

- **`enum sccm`** — walks CN=System Management,CN=System,<base> for SCCM
  Management Points + Distribution Points + `ms-SMS-MP-Name` + Site Codes.
  Adds NAA (Network Access Account) discovery if a policy request endpoint is
  exposed (foundation for 1.4.5 SCCM chapter).
- **`enum scom`** — walks CN=OperationsManager (custom schema extension if
  installed) for management servers + agent-deployed hosts + gateway servers.
- **Effort:** M (2-3 d). No new sibling protocol crates.

### WS-G — DNS record CRUD (ADIDNS write)

Extend the read-only `enum dns` primitive with a write side. IronEye ships
this; we don't. Landing here closes the DACL-Attacks-II adjacent gap.

- **`attack dns --add-a <name> --ip <a.b.c.d>`** — create an A record via
  LDAP write to `dnsRecord` attribute in `DomainDnsZones` partition.
- **`attack dns --modify-a <name> --ip <new>`** — replace target of existing A.
- **`attack dns --tombstone <name>`** — soft-delete (set dNSTombstoned=TRUE).
- **`attack dns --delete <name>`** — hard-delete via LDAP delete.
- Applies to both `DomainDnsZones` + `ForestDnsZones` partitions (auto-detect).
- **Effort:** S-M (2 d). Reuses existing `Collector` LDAP surface + a new
  `dns_record::build_a_record()` helper for the wire-format blob.

### WS-H — Interactive `krb5.conf` generator

UX polish surfaced by IronEye — first-time Kerberos operators appreciate a
"just make it work" onboarding path.

- **`adhammer setup krb5`** — new top-level command that:
  1. Prompts for realm name (auto-suggests from current session's DNS domain if any)
  2. Scans the domain for DCs (via `enum sessions` internal probe or existing scan collector)
  3. Emits a valid krb5.conf to `~/.krb5.conf` (or `%APPDATA%\krb5.conf` on Windows)
  4. Prints the `KRB5_CONFIG=…` env var line for shells that don't auto-pick-up
- **Effort:** S (~1 d). Pure UX helper, no wire code.

### WS-E — Legacy DC validation matrix

Lab spin-up + regression suite covering Server 2016 / 2019 / 2022 alongside the
existing 2025 DC01. Unblocks positive Zerologon / noPac validation (WS-A), and
seeds the "works on every Windows Server" claim in launch copy + docs/certs.

- 3 new DC VMs (mkdc-style unattended install), joined to `testlab.local` as
  child domains (`legacy16.testlab.local`, `legacy19.testlab.local`,
  `legacy22.testlab.local`) — so cross-domain paths get validation too.
- Regression suite: `adhammer scan` + core `attack` + `enum` per DC, captured to
  `docs/matrix-2016.md` etc.
- **Effort:** M (3 d + one-time lab setup for 3 more DCs).

## Ship sequence

- **Day 1:** WS-E — lab spin-up (unblocks WS-A positive validation).
- **Days 2-6:** WS-A parallel with WS-D (independent).
- **Days 7-10:** WS-B (needs 1.4.1 WS-6 landed first).
- **Days 11-12:** WS-C.
- **Day 13:** cut, tag, publish batch (bottom-up dep chain — dcerpc → sub-crates → cli).

## Assets to build for the launch

- Legacy DC matrix table (`docs/dc-matrix.md`) — 4 columns × N attacks.
- Zerologon + noPac live-run GIFs (asciicast → agg via WSL Kali).
- Forest trust chain diagram (SVG).
- X thread: "AD tools skip the pre-2022 CVEs by default. adhammer 1.4.2 doesn't."
- CHANGELOG.md entry listing the 4-DC matrix + both CVEs + forest trust chain.

## Non-goals for v1.4.2

- MSSQL / Exchange / SCCM v2 (done in 1.4.1 WS-1)
- New protocol crates beyond `krb-listen`
- GUI / TUI polish
- Cloud / Entra ID / AD FS (explicitly out of scope for the entire 1.4.x family)

## Success signals

- 4/4 Windows Server matrix greens (2016/2019/2022/2025) on `adhammer scan`
- Both classic CVEs positive-validated on legacy DC → PoC screenshot in release notes
- Cross-forest DA in < 60s from initial forest DA
- `krb-listen` on crates.io as standalone tool + one-line `cargo add`

## Risks

- WS-E lab is a real hardware/VM commitment. Alternative: Vagrant images from `mkdc/`.
- WS-B cross-realm ticket format is under-documented; may need packet-capture-guided
  implementation. Fallback: read `krb5-ticket-forge` docs + Windows KDC trace ETW.
- Zerologon is patched-and-enforced on modern DCs — negative-only validation on 2025.
- noPac needs MAQ > 0 (default). Some enterprises set MAQ = 0 → tool must correctly
  report "MAQ = 0, noPac blocked."
