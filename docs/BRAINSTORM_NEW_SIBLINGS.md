# ADhammer sibling ecosystem — new-crate brainstorm (2026-09-03)

**Purpose:** identify pentest primitives adhammer users would benefit from,
where nothing exists (or nothing maintained) in the Rust ecosystem yet, and
that would fit as a **new sibling crate** in the icedracon family — not a
feature bolted onto adhammer, not a fork of an existing crate.

**Ground rules for candidate selection** (per your working-style memories):

- Prefer minimalism — hand-rolled ~200–500 LOC over adding popular libs,
  ripgrep-level dep trees ([[feedback-stier-minimalism]]).
- Dual-use test — every offensive primitive must have a defensive read
  ([[feedback-adhammer-hard-rules]]).
- No AI features (WS-21/22 already rejected).
- Novel over "yet another impl" — if a maintained Rust crate exists that
  meets the bar, use it, don't sibling it. Never name a competitor in the
  pitch ([[feedback-no-competitor-mentions]]).
- Pentester-first UX — pitch by what the crate does for the operator, not
  by what tool it replaces.

---

## 1. What the ecosystem already covers (do NOT re-do)

MS-* protocol coverage is essentially complete (30+ sibling crates):

- **Transport / auth**: `smb2-client`, `dcerpc`, `ntlmssp`, `ms-ndr`, `ms-kile-fast` (Kerberos FAST/preauth), `ms-pkca` (PKINIT), `ms-nrpc` (Netlogon), `picky-krb`
- **Directory / access**: `ms-lsad`, `ms-lsat`, `ms-drsr` (DRS Replication), `ms-samr` (via dcerpc), `ldap3-ntlmssp`, `windows-sddl`, `ad-acl`
- **Ticket / cred artefacts**: `ms-pac`, `ms-pac-forge`, `ccache-io`, `dpapi-offline`, `dpapi-ng`, `ms-gkdi`, `ms-bkrp` (backup key), `hashglass`
- **PKI / ADCS**: `ms-crtd`, `ms-icpr`, `ms-csra`, `gpo-forge`
- **Exec / lateral**: `ms-scmr`, `ms-tsch`, `ms-wmi`, `ms-dcom`, `ms-tds`
- **Coercion**: `ms-coerce` (RPRN + EFSR + FSRVP + DFSNM)
- **DNS + zones**: `ms-dnsp`
- **Event / audit**: `ms-even6`
- **RODC-specific**: `ms-rodc`

**Adhammer-CLI surface** already covers: LDAP collect + BloodHound-CE export, 58-check registry, ESC1/4/6/8/10/11/15/16, Kerberoast/AS-REP, Zerologon, Shadow Credentials, DCShadow, BadSuccessor (Server 2025 dMSA), Diamond/Golden/Silver, RBCD, DCSync, WMI/AtExec/WinRM, MSSQL TDS, GPP walk, LAPS/gMSA dump, ADCS-relay, coercion (now with `--scan-all`), no-cred discovery (`run --deep`, `enum host/nullbind/rpc-null/shares/web/sysvol`), hashglass annotation.

That is a **remarkably** wide surface. Real gaps are outside MS-* protocol land.

---

## 2. Where the ecosystem has real gaps

### Gap A — Network-poisoning surface (link-local NTLM/hash capture)

The single largest gap. Every internal-network engagement in the world
starts with a link-local poisoning tool. Nothing Rust-native exists.

| Sibling name | What it does | Rust availability | Fit |
|---|---|---|---|
| **`llmnr-poison`** | LLMNR (UDP 5355 mDNS-like), NBT-NS (UDP 137), mDNS (UDP 5353) responder. Reply to any query with the attacker IP; capture the follow-up SMB/HTTP NTLM auth. Emit NetNTLMv2 lines annotated by `hashglass` (mode 5600) ready to pipe to hashcat, or to `adhammer attack relay` for onward relay. Dual-use: `--defensive-scan` mode listens *without* replying and lists what queries the segment leaks (privacy audit). | none maintained | 300–500 LOC (raw UDP + name-parser); dep tree = tokio + hand-rolled |
| **`mitm6-core`** | DHCPv6 server + ICMPv6 Router Advertisement generator + WPAD `wpad.dat` responder. Wins the Windows-default "IPv6 preferred" race and steers proxy traffic through the attacker. Pairs with `attack relay` for auto-NTLM-to-LDAPS. Dual-use: `--defensive-scan` reports RA/DHCPv6 auth state + rogue-RA guard status. | none maintained | ~600 LOC (raw AF_PACKET or `socket2` + hand-rolled ICMPv6/DHCPv6 packers); dep = `socket2` — bigger but justified |
| **`wpad-serve`** | Standalone HTTP WPAD responder if operator wants the WPAD half without full mitm6 (segment already IPv6-clean, just missing WPAD). Could be a feature-flag of `mitm6-core` instead. | none | ~150 LOC — probably feature-flag |

**Priority: highest.** These would let adhammer's `run` verb be a genuine
"internal-recon black box" instead of only reading DNS + probing DCs.

### Gap B — Kerberos-relay primitives

The novel-technique frontier. The current `attack relay` (from 1.4.8-D
WS-NTLMRELAYX-SMB-LDAP) covers NTLM. Kerberos relay is a rarer, newer
class with almost no cross-platform tooling.

| Sibling name | What it does | Rust availability | Fit |
|---|---|---|---|
| **`krb-relay-rs`** | Intercept a Kerberos AP-REQ authenticator arriving over one RPC binding, forward it to a different SPN (SPN-less RPC / SCMR / ICPR) to gain a foreign-service session. Composes with `attack coerce` (Kerberos-shaped variant) and `ms-icpr` for AD CS. | none | HARD, ~1000 LOC — needs SPN-diversion inside `dcerpc` transport layer; also needs ms-krb "unwrap AP-REQ, replay to peer" primitive |
| **`pkinit-relay`** | Extend Kerberos: capture PKINIT AS-REQ from a coerced host (or NTLM-relayed enrollment) → forward. Very rare. Pairs with existing shadow-credentials pipeline. | none | HARD, ~800 LOC |

**Priority: high but expensive.** Would put icedracon on the map for
Kerberos-relay tradecraft, but the LOC + review burden is significant.
Best after mitm6/LLMNR ship.

### Gap C — Post-exploit credential harvesting (offline, from evidence)

Adhammer has `dpapi-offline` and `ms-bkrp` — the crypto is solved. What's
missing is the *offline evidence parsers* that consume Windows artefact
formats and hand blobs to those crypto crates.

| Sibling name | What it does | Rust availability | Fit |
|---|---|---|---|
| **`browser-creds-offline`** | Offline extractor for Chrome / Edge / Chromium `Login Data` (SQLite) + Firefox `logins.json` + `key4.db`. Feeds DPAPI-encrypted blobs to `dpapi-offline` for decrypt. Consumes an evidence directory (a triage collection), never touches a live browser process. Dual-use: exact same code path is a DFIR triage report. | none as a Rust crate; several ad-hoc Go/Python impls | 400–800 LOC — needs a slim SQLite reader (or `rusqlite` if you accept the bigger dep) + `serde_json` for Firefox |
| **`reg-hive-parse`** | Read HKLM\SAM + HKLM\SECURITY + HKLM\SYSTEM hives offline (raw hive-file parser). Extract SAM local user hashes, LSA secrets (SysKey + cached MSV), machine account key. Feeds ms-pac / secretsdump pipeline. Complements adhammer's remote-registry check. Dual-use: forensic reg viewer. | there's `nom-based hivex` bindings; no clean Rust-native  | 500–1000 LOC — hive-file format is well documented but nontrivial |
| **`ntds-parse`** | Offline `NTDS.dit` (ESE database) parser to extract every AD account NT hash + Kerberos keys. Consumes a triage extract; complements online DCSync. | `ese-parser` exists in the ecosystem — see [[reference-falcon-rust-patterns]]; NTDS-specific wrapper is missing | 200–400 LOC on top of `ese-parser` |

**Priority: high.** Every real engagement produces offline evidence
extracts; these three would let adhammer operate on that evidence without
network round-trips.

### Gap D — Rule packs (curated attack knowledge as data, not code)

| Sibling name | What it does | Fit |
|---|---|---|
| **`ad-cs-esc-registry`** | YAML/JSON rule pack of every AD CS ESC family (ESC1..16 + newer as they land). Each rule = template attribute predicate + severity + hashcat-mode + remediation. Adhammer's `check adcs` loads the pack instead of hard-coding. Community-updatable without a new adhammer release. | 200 LOC (loader) + N rules — matches `ms-crtd` shape |
| **`ad-trust-rules`** | Same pattern for cross-forest / SID-history / trust-key attacks (GoldenGMSA, SIDHistory injection, foreign-security-principals abuse). Newer surface (2024+). | 200 LOC + N rules |
| **`kerb-etype-audit`** | Rule pack for Kerberos etype negotiation: flags RC4-HMAC-fallback, weak preauth, missing FAST. Adhammer reads + reports; no active attack. Pure defensive-audit dual-use. | 150 LOC + rules |

**Priority: medium-high.** Very fast to ship, high user impact (they're
attacked-target-rules, not new protocol wire code).

### Gap E — [REMOVED]

*(Was proposing Azure/Entra siblings — a permanent scope-kill from
`project_adhammer.md` "Azure / Entra ID / AAD Connect — PERMANENTLY
KILLED. Different auth model, different tools, different product.
Never." Do not revisit.)*

### Gap F — Missing single-CVE workflow verbs (small)

Not new siblings — but new adhammer CLI verbs pinned to specific CVEs
that don't have first-class flows yet.

| Verb | CVE / class | What's needed | Where |
|---|---|---|---|
| **`attack nopac`** | CVE-2021-42278 / CVE-2021-42287 (sAMAccountName spoofing) | Machine-account creation via SAMR + rename dance + S4U — every primitive already exists in existing siblings. Pure adhammer glue. | ~200 LOC in `cli/src/attacks/nopac.rs` |
| **`attack ntlm-mic-drop`** | CVE-2019-1040 (NTLM MIC removal for cross-service relay) | Extension to existing `attack relay` — one flag on the NTLMSSP payload build. | ~50 LOC in `cli/src/attacks/relay.rs` |
| **`attack esc13`** | ADCS ESC13 (Issuance Policy → group membership) | Read cert templates for msPKI-Certificate-Policy + linkedOID mapping; new rule in `ms-crtd` pack. | ~150 LOC — belongs to `ad-cs-esc-registry` if we ship that |

**Priority: high, tiny scope.** These are single-session workstreams and
should be commit-per-verb, not a batch.

### Gap G — Reporting / operator UX

| Sibling name | What it does | Rust availability | Fit |
|---|---|---|---|
| **`attack-graph-tui`** | Real-time terminal attack-path visualizer. As adhammer `run --deep --web` progresses, node colors change (probe running → refused → exposed). Consumes the same JSON adhammer already emits. Dual-use: replay from an old scan JSON to show the paper trail. | `ratatui` exists but nobody's built the specific "attack path" widget set | 500–800 LOC on top of `ratatui` — bigger dep but justified for TUI |
| **`session-diff`** | Diff two adhammer JSON reports for regression tracking (already partially covered by adhammer `--baseline`, but a standalone crate would let downstream tools consume it). | none | 200 LOC |

**Priority: medium.** UX polish, not attack surface. Nice-to-have.

---

## 3. Ranked candidates by evidence-weighted EV

Scoring: (impact 1–5) × (Rust-availability void 1–3) ÷ (LOC / 500).
Higher = more sibling worth building next.

| Rank | Candidate | Impact | Void | LOC | Score | Notes |
|---:|---|---:|---:|---:|---:|---|
| 1 | `llmnr-poison` | 5 | 3 | 400 | **18.8** | Every internal engagement uses this class of tool. First Rust impl. Small dep tree. |
| 2 | `mitm6-core` | 5 | 3 | 600 | **12.5** | Already deferred from 1.5.0 → 1.5.1 explicitly. Needs `socket2`. |
| 3 | `attack nopac` (verb, not sibling) | 4 | 2 | 200 | **20.0** | Free: reuses existing siblings. Ship in 1.5.x. |
| 4 | `browser-creds-offline` | 4 | 3 | 600 | **10.0** | Composes with existing dpapi-offline. Real post-exploit yield. |
| 5 | `ad-cs-esc-registry` | 4 | 2 | 200 | **20.0** | Fast to ship. Community-updatable rule pack. |
| 6 | `reg-hive-parse` | 4 | 2 | 800 | **5.0** | Enables offline SAM/LSA extraction, feeds ms-pac. |
| 7 | `ntds-parse` | 4 | 2 | 300 | **13.3** | Thin wrapper over `ese-parser`. High yield. |
| 8 | `attack ntlm-mic-drop` (verb) | 3 | 2 | 50 | **60.0** | Tiny flag on existing relay. Highest bang-for-LOC. |
| 9 | `attack esc13` (verb, uses new rule pack) | 3 | 2 | 150 | **20.0** | With `ad-cs-esc-registry` ships as one pattern. |
| 10 | `attack-graph-tui` | 3 | 3 | 800 | **5.6** | UX. Real user delight. |
| 11 | `krb-relay-rs` | 4 | 3 | 1000 | **6.0** | Novel tradecraft; expensive; do after network-poisoning siblings ship. |

---

## 4. Concrete 1.5.x roadmap based on this brainstorm

The verbs in Gap F have the highest score/LOC ratio and reuse existing
siblings — do them first. The network-poisoning family (Gap A) is the
strategic frontier and should be its own 1.6.0 or 1.5.1 workstream.

### 1.5.1 candidate scope (2–3 sessions)

- `attack nopac` — CVE-2021-42278/42287, in-adhammer verb
- `attack ntlm-mic-drop` — extend `attack relay`
- `ad-cs-esc-registry` — new sibling (rule pack)
- `attack esc13` — new adhammer verb consuming the rule pack

Total: 1 new sibling, 3 adhammer verbs. ~700 LOC. Every dep already known.

### 1.6.0 candidate scope (network-poisoning family)

- `llmnr-poison` sibling — LLMNR/NBT-NS/mDNS responder
- `mitm6-core` sibling — DHCPv6 + WPAD + RA
- adhammer `attack poison-net` verb that composes both + `attack relay`
- adhammer `run --defensive-scan` mode that uses same siblings in listen-only

Total: 2 new siblings, 2 adhammer verbs. ~1200 LOC. New dep: `socket2` (widely audited, fits the ripgrep-level bar).

### 1.6.x deferred candidates (own workstream each)

- `browser-creds-offline` + `reg-hive-parse` + `ntds-parse` — post-exploit
  triage family. Compose into `adhammer triage <evidence-dir>`.
- `krb-relay-rs` — after network-poisoning ships.

---

## 5. Explicit non-goals (don't build these)

- **Azure / Entra ID / AAD / AAD Connect / hybrid AD / AD FS / vSphere —
  PERMANENTLY KILLED, never revisit.** Different auth model, different
  tools, different product. Any candidate crate touching these is
  automatically out of scope regardless of technical merit. Source of
  truth: `project_adhammer.md` and
  [[feedback-adhammer-no-cloud-ever]].
- **Anything replicating an existing well-maintained Rust crate** — no
  yet-another-`kdbx`, yet-another-`sqlite3`, yet-another-`rustls`. The
  ecosystem's whole point is the *MS-* protocol gap, which is filled.
- **Ephemeral CVE-of-the-week PoCs** — those go into `attack <name>`
  adhammer verbs when they're stable, not into new siblings.
- **AV/EDR evasion primitives** — direct-syscall crates etc. Rejected per
  [[feedback-adhammer-hard-rules]] (dual-use rule doesn't apply cleanly).
- **AI-in-the-loop features** — WS-21/22 rejected; still rejected.
- **Blue-team-only rule engines** (Sigma, MITRE mapping) that don't have
  a dual-use offensive read.

---

## 6. Next-step gate

Nothing in this document is authorization to build. Each candidate:

1. Needs its own version-contract plan (`docs/PLAN_<crate>.md`) with
   exact scope, non-goals, security boundary, and threat-model note per
   `AI_RELEASE_GOVERNANCE.md` §3.
2. Needs your explicit go-ahead per §1.
3. Follows the standing publish discipline (bottom-up cascade, receipts,
   scrubber).

The purpose here was **only** to answer "what's actually missing that we
should build next" with evidence, not to guess.
