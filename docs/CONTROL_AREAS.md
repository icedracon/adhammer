# AD-Pentest Control Areas (`ADP-01` .. `ADP-30`)

**In-house taxonomy** for organizing every ADhammer check + attack verb by the
pentest control area it exercises. Names are ADhammer's own — no third-party
cert-body / methodology labels — so the taxonomy is stable, versionable, and
mappable to whatever industry framework a downstream consumer prefers.

The taxonomy is machine-enforced in two places:

- `crates/report/src/check_meta.rs::CONTROL_AREAS` lists every valid code.
- A CI-gated test asserts every check in `adhammer_checks::registry()` carries
  at least one control-area code from this list and a valid kill-chain phase.
  A new check without both fails `cargo test`.

## Kill-chain phases

Every check + attack also carries one **kill-chain phase**, using generic
attacker-lifecycle terminology (no cert-body naming). Valid values are the
strings in `crates/report/src/check_meta.rs::KILL_CHAIN_PHASES`:

- `enumeration` — read-only discovery, no bind required or one-shot low-priv
  bind (RootDSE, DNS zones, anonymous LDAP, PreWin2000 group, dSHeuristics).
- `initial-access` — first foothold on the estate (AS-REP roast without prior
  creds, PASSWD_NOTREQD, weak password policy, guest-account abuse).
- `privilege-escalation` — escalate within the domain (Kerberoast, ESC1-15,
  Shadow Credentials, RBCD, Machine Account Quota abuse).
- `lateral-movement` — moving between hosts (broad LAPS gaps, GPO abuse,
  stale computers, duplicate SPN hijack).
- `persistence` — stay in (silver ticket, key-cred plant on admin,
  primaryGroupID hijack, disabled-but-privileged accounts).
- `domain-dominance` — full domain / forest control (DCSync, krbtgt hash
  extraction, unconstrained delegation on non-DC, trust SID filtering off).

The report's kill-chain-coverage panel emits phases in the canonical lifecycle
order above (attacker walks left-to-right), not alphabetical.

---

## Control areas

### `ADP-01` — Passive Enumeration

Discovery attacks that need no credentials, or that a low-priv account can
run trivially. RootDSE fingerprint, anonymous LDAP bind, DNS zone dump.

### `ADP-02` — User & Computer Enumeration

Full account inventory via SAMR, LSAT, or Pre-Windows 2000 Compatible Access
group leakage. Feeds every downstream spray / roast attack.

### `ADP-03` — Group & ACL Enumeration

Membership + ACL walk that surfaces control paths without ever running an
attack — the DCSync path, SDProp exclusion, primaryGroupID hijack readable.

### `ADP-04` — Delegation Configuration

Unconstrained, constrained (S4U2Proxy), and resource-based (RBCD)
delegation. Includes MachineAccountQuota abuse that plants an RBCD writer.

### `ADP-05` — Kerberos Pre-Auth & Roasting

AS-REP roasting (DONT_REQ_PREAUTH) + Kerberoast (SPN-bound users + admins).
Includes duplicate-SPN class as an integrity issue.

### `ADP-06` — Credential Exposure

Passwords sitting where any authenticated user can read them: gMSA readable
by broad principals, LAPS misdeployment, GPP cpassword in SYSVOL, service
password in a user's description field.

### `ADP-07` — Password Policy

Weak default domain policy, FGPP weaker than default, non-expiring passwords
on privileged accounts, PASSWD_NOTREQD, stale (2yr+) passwords.

### `ADP-08` — Reversible Encryption

Per-account `ENCRYPTED_TEXT_PWD_ALLOWED` + domain-wide
`DOMAIN_PASSWORD_STORE_CLEARTEXT` — cleartext-password extraction from the DIT.

### `ADP-09` — Weak Kerberos Ciphers

RC4-only service accounts, `USE_DES_KEY_ONLY`, RC4 trust encryption, obsolete
functional level that blocks AES.

### `ADP-10` — LDAP Signing / Channel Binding

Server-side controls that prevent NTLM relay to LDAP / LDAPS. Includes the
dSHeuristics anonymous-bind override.

### `ADP-11` — SMB Signing / Message Integrity

Server-side SMB signing / message-integrity requirements. Placeholder for
future active probes (currently no static registry check emits an
`ADP-11`-only tag; the DC posture live-probe fills this dimension at scan
time).

### `ADP-12` — Certificate Services Templates (ESC1-15)

The full ADCS ESC family: enrollee-supplies-subject, low-priv enrollment ACL,
EKU manipulation, ESC15 / EKUwu, weak key size.

### `ADP-13` — Certificate Template Configuration

Template-level policy (manager approval, template-schema version, enrollment
flags). Complements ADP-12; a well-configured template negates most of the
ESC1-15 attack surface.

### `ADP-14` — Machine Account Quota

Any-user computer creation right. Enables downstream RBCD / delegation
attacks (see also `ADP-04`).

### `ADP-15` — Coercion Primitives

Server-side handles for coercing a DC (or member) to authenticate to a
listener: MS-EFSR / PetitPotam, Print Spooler / PrinterBug. Feeds
`ADP-16` NTLM relay.

### `ADP-16` — NTLM Relay

Handles NTLM messages the DC will accept from a relay victim. Distinct from
ADP-10 (signing/CBT) — this dimension covers the target-side ingestion of
the relayed auth (ESC8 web enrollment, LDAP, RBCD write).

### `ADP-17` — DCSync Rights

`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` on the
domain naming context. Only Domain Controllers should hold these.

### `ADP-18` — Shadow Credentials

`msDS-KeyCredentialLink` write ACEs on privileged targets. Covers both the
attack shape (PKINIT with attacker's key) and the enabler check (Key Admins
group population).

### `ADP-19` — DCShadow

Registering a rogue DC to inject replicated updates. LDAP path is dead on
2019+ per live validation; a modern DRSUAPI-based variant lives here for
future work.

### `ADP-20` — Golden / Silver / Diamond / Sapphire Ticket Forge

Forge a TGT under `krbtgt` (golden) or a TGS under a service account key
(silver). Enabler classes: `krbtgt` password age, machine-account password
rotation stall.

### `ADP-21` — Pass-the-Ticket / Pass-the-Hash / Overpass

Replay an existing ticket or NTLM hash. Static enablers are all NTLM-cache
hardening classes (Protected Users adoption, admin `NOT_DELEGATED`).

### `ADP-22` — Tier-0 Group Population

Domain Admins / Enterprise Admins / Schema Admins direct membership hygiene,
including hidden-membership vectors (`primaryGroupID`, SIDHistory-derived
Tier-0, computer accounts in Tier-0, cross-forest principals in Tier-0).

### `ADP-23` — Sensitive Group Hygiene

Non-DA groups that transitively reach DA: Backup / Server / Print /
Account Operators, Cert Publishers, Key Admins.

### `ADP-24` — Protected Users Adoption

Uses of the Protected Users group + membership of Tier-0 accounts in it, +
built-in admin exclusion caveats.

### `ADP-25` — Trust Configuration

SID filtering, selective auth, RC4 trust encryption, TGT delegation, external
trust transitivity. Cross-forest Tier-0 injection lives here.

### `ADP-26` — Dormant / Stale Accounts

Users / computers that haven't logged on recently, never-logged-on accounts,
disabled-but-still-privileged accounts.

### `ADP-27` — Machine Password Rotation

Machine-account password age (stale hash → silver ticket persistence,
Zerologon relay window widens). Also LAPS-expired-but-not-rotated.

### `ADP-28` — krbtgt Password Rotation

`krbtgt` account password age. Directly feeds `ADP-20` golden-ticket
persistence — old `krbtgt` hashes never expire until rotated twice.

### `ADP-29` — dMSA / BadSuccessor

Server 2025's Delegated Managed Service Accounts and the `badSuccessor`
inheritance abuse (CVE-2024-BadSuccessor).

### `ADP-30` — GPO Ownership / Creation Rights

Group Policy Creator Owners population, GPO OU-link write ACEs, GPO
delegation reachable from non-admin principals. Feeds lateral-movement
via GPO startup scripts / scheduled-task deployment.

---

## Extending the taxonomy

To add a new code:

1. Add the `ADP-NN` entry (with its short comment) to `CONTROL_AREAS` in
   `crates/report/src/check_meta.rs`.
2. Add a `### ADP-NN — <title>` section to this document.
3. Reference the code from the relevant `CheckMeta` entries in the same file.

The CI gate (`ws_ctrlmap_tests::all_control_area_tags_are_declared`) will
fail if a check references a code not in `CONTROL_AREAS`, so step 1 has to
happen before step 3 — enforced automatically.

## Extending the kill-chain phase set

Add to `KILL_CHAIN_PHASES` in the same file. Order matters — the coverage
panel emits phases in that array order, not alphabetical, so keep the
attacker-lifecycle flow: enumeration → initial-access → privilege-escalation
→ lateral-movement → persistence → domain-dominance.
