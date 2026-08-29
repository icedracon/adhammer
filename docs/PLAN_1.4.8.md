# ADhammer 1.4.8 — hard plan

Post-1.4.7 ship, 2026-08-29. Every item names a concrete deliverable + acceptance
test + effort estimate. Items are ordered by ship priority, not category.
The tail (**Non-goals** + **Deferred**) is deliberately loud — this release
finishes what 1.4.7 self-flagged, it does not open new territory.

## 1. ~~WS-4-P2-CLOSE~~ — CUT in 1.4.8

Static-analysis pass in 1.4.8 tried three more wrap-token layout hypotheses
after the 1.4.7 partial fix; every one produced the identical `SMB2 status
0xC00000AE (STATUS_PIPE_BUSY)`. DC-side response is binary — accept or
reject — with no informational discrimination, so blind hypothesis search
is dead. Rather than ship the `[SCAFFOLDING]` label indefinitely,
**`check krb-seal` + `AesCts96Sealer` + the `rpc_seal` RFC 3961/3962
primitives were cut from main** (deletion commit in 1.4.8's log; git
history preserves everything at tag `v1.4.7` and earlier).

**Resurrection path** — bring the code back the day someone lands a
Windows-native → DC Wireshark capture over `\PIPE\lsarpc` under
Kerberos-sealed, so the sender-side byte diff is visible on paper
instead of guessed at. The capture path stays the same as documented:
interactive RDP + pktmon, or `sshpass`-driven remote invocation from a
domain-joined Windows client.

## 2. WS-SCAN-ONLY-FILTER — enable 0-vuln live-render

Add `scan --only <check-id>[,<check-id>...]` and inverse `scan --skip
<check-id>[,<check-id>...]`. Selects a subset of the 58-check registry
before the run. Same flag lets an operator re-run just what tripped last
time — narrow diagnostic loop.

**Files:** `cli/src/attacks/scan.rs`,
`crates/checks/src/lib.rs::run_all_with_coverage`.
**Acceptance:**
- `scan --only P-KerberoastAdmin` runs exactly one check, coverage row
  shows one entry.
- `scan --only <k1>,<k2>` where both are known-clean on the lab DC
  renders the green **hardened-bill-of-health** banner live.
- Existing behavior unchanged when neither flag is passed.
**Effort:** ~40-60 lines + 3 new tests.

## 3. WS-WIRE-TRACE — per-PDU tracing in dcerpc / smb2-client / ntlmssp

Turn the honestly-documented placebo warning on `-vvv` (from 1.4.7 P2-E)
into real coverage. Bounded scope per crate:

- **dcerpc**: BIND / BIND_ACK / AUTH3 send + recv (bytes, fragment_len,
  call_id, packet_type, auth_length).
- **smb2-client**: SESSION_SETUP + TREE_CONNECT + IOCTL for named-pipe
  RPC (command, credit_charge, message_id, session_id, tree_id, status).
- **ntlmssp**: Type1 / Type2 / Type3 message assembly (message_type,
  negotiate_flags, target_name len, workstation len).

Same redaction discipline as WS-KRB-TRACE: identifiers + counts + status
codes only; never body payload, never credentials, never key material.

**Files:** `dcerpc/src/**` + `smb2-client/src/**` + `ntlmssp/src/**`
(upstream patch bumps) then ADhammer workspace-pin bumps + `cargo update`.
**Acceptance:** `-vvv scan` against a live DC emits at least 20 wire TRACE
lines from these three crates combined, all pass a `grep -vE
'password|hash|ticket|key_bytes|session_key'` audit filter.
**Effort:** ~1-2 days including publish cascade.

## 4. WS-BINSTALL — `cargo binstall adhammer` support

Zero-cost fix for the `cargo install adhammer` compile-then-quarantine
loop on Windows. Ship prebuilt binaries as GitHub release attachments; a
GitHub Actions matrix builds them from the tagged source. Users with
`cargo binstall` skip the local rustc invocation entirely (which still
leaves Defender to scan the downloaded binary, but at least without a
90-second compile first).

**Files:** `.github/workflows/release.yml` (new). Targets:
`x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`. Also emit SHA-256 sums + a sigstore
attestation (free via GitHub Actions OIDC).
**Acceptance:** `git push origin v1.4.8` triggers the release workflow,
which uploads three platform binaries + `.sha256` + `.sig` files to the
GitHub Release page. `cargo binstall adhammer` on each of the three
platforms lands the binary in `~/.cargo/bin` in under 15 seconds.
**Effort:** ~4-8h CI iteration.

## 5. WS-INSTALL-PS1 — one-liner Windows install

Wrap the Defender-exclusion dance into a script hosted on the project
site. User runs one line:

```
iwr https://icedracon.github.io/adhammer/install.ps1 | iex
```

The script adds a scoped exclusion for `~\.cargo\bin`, runs `cargo
binstall adhammer` (or `cargo install adhammer` fallback), removes the
exclusion, prints the binary path + `--version`. Idempotent; safe to
re-run.

**Files:** `docs/install.ps1` (new), README `## 📥 Install` section
update.
**Acceptance:** on a fresh Windows 11 with only `cargo` installed, the
one-liner completes without user prompts and `adhammer --version` prints
`adhammer 1.4.8`.
**Effort:** ~30 lines PS + docs polish.

## 6. WS-CHECK-STAGES — rich stages on `check` verbs

Consistency with `attack` verbs. `check adcs` and `check krb-seal`
currently print raw finding lines with no per-stage narration; every
`attack` wraps its impl in `run_action_with_brief` per 1.4.6.

**Files:** `cli/src/checks/adcs.rs`, `cli/src/checks/krb_seal.rs`,
possibly a shared `checks/mod.rs::run_check_with_brief`.
**Acceptance:** `check adcs --text` emits a StageChecklist card
(`resolve-ldap → collect-templates → rule-pack → render`) with per-stage
green/red status.
**Effort:** ~60-80 lines.

## 7. WS-COVERAGE-70 — lab seed 50 → 60%+

29/58 tripped today; 29 clean. Focus on the two cheapest buckets:

- **7 stale/dormant checks**: backdate `lastLogon` / `pwdLastSet` /
  `whenChanged` on seeded principals via `ldapmodify` on the lab DC. No
  new principals needed.
- **5 seedable-with-more-investigation checks**: audit against
  `crates/checks/src/lib.rs::run_all` for which checks need what LDAP
  attribute state, then seed each.

Leave the 12 ESC cert-template + 5 trust buckets for a later pass — both
require heavier lab setup (CA install / second forest).

**Files:** `adhammer_lab_seed/` (external repo).
**Acceptance:** `scan` against the lab DC finds ≥ 40 findings (currently
29). Coverage matrix has ≤ 18 clean rows.
**Effort:** ~4-8h lab work + a `adhammer_lab_seed` version bump.

## 8. WS-DEFENDER-SUBMIT — false-positive queue submission

Manual for 1.4.8; automate in 1.4.9 if the manual submission actually
clears. Submit each release SHA-256 to the Microsoft Security
Intelligence FP queue. Time-cheap, works on Microsoft's schedule (weeks
to months).

**Files:** `docs/RELEASE_CHECKLIST.md` (new), one line per release.
**Acceptance:** ship notice includes a Microsoft submission tracking
number.
**Effort:** ~1h per release.

---

## Non-goals — will NOT ship in 1.4.8

- **No EV code-signing certificate.** Real fix for Defender, ~$300/year,
  no budget. Revisit for 1.4.9 or later.
- **No new attack classes for surface expansion.** 58 checks with proof
  discipline beats 100 half-verified.
- **No BloodHound-CE ingest polish.** No downstream schema movement.
- **No CI/CD template repos.** Zero demand signal from downstream users.
- **No video walkthrough / marketing surface.** Ship-first, market-later.

## Deferred — not 1.4.8, ask separately

- **SCCM / MECM abuse.** New territory, needs lab SCCM install. Deserves
  its own scope decision if it happens at all.
- **`adhammer-sdk` API stability commitment.** Zero downstream adopters
  today; premature. Revisit when there is real downstream pain.
- **WS-WIN32-MIN-ADOPT.** Adopt the icedracon 2026-08-29 `windows-*`
  wave. Would give that ecosystem its first real downstream consumer,
  but not on the 1.4.7 tail. Ship in a follow-up focused on ecosystem
  dogfooding.

## Killed

- **ADFS / Entra ID / AAD Connect attack surface.** Scope explosion,
  different auth model, different tools. Not this product.
