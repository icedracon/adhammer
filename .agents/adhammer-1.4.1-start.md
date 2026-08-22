# adhammer 1.4.1 — "start here Monday" kickoff

**Status:** unblocked, 1.3.10 live on crates.io + tag pushed 2026-08-23.
**Target ship:** early October 2026 (4-6 weeks after 1.3.10 to let launch traffic settle).
**Version:** `v1.4.1` — 1.4.0 stays permanently yanked on crates.io (2026-08-13 yank, memory).
**Branding:** carry the AD//HAMMER wordmark + blue-cyan `#2ea8ff` established for the 1.3.10 site rebrand.

## The one-line

*"Every AD attack CAPE tests, in one static binary — now with modern-Windows DCShadow, cross-forest Kerberos, and MSSQL/Exchange/SCCM lateral."*

## Scope in three tiers

**Tier 1 — the shipped 1.4.1 promise** (from `.agents/adhammer-1.4.1-plan.md`; each WS is a *feature* release users see):

| WS | What | Effort | Blocks |
|---|---|---|---|
| WS-1 | MSSQL / Exchange / SCCM attacks (CAPE module) | L (5-7d) | none — WS-1 can start day 1 |
| WS-2 | DCShadow via DRSUAPI (replaces dead LDAP-path on 2019+) | XL (8-10d) | needs live 2019+2022+2025 DC (already have 2022+2025) |
| WS-3 | Cross-forest / trust — `--foreign-sid`, `--allow-cross-trust` | S-M (2-3d) | needs 2nd forest DC (or trust between existing pair) |
| WS-4 | Kerberos sealed bind in dcerpc | L (5-6d) | rabbit-hole risk; timebox strictly |
| WS-5 | DACL Attacks II (write-owner, write-dacl, primary-group, gpo-link-modify, allowed-to-act) | M (4d) | none |

**Tier 2 — boss-review arch/UX carryover from 1.3.10** (refactors, no user-visible change — the invisible-but-necessary work):

| ID | What | Effort | Rationale |
|---|---|---|---|
| arch-0 | Split `cli/src/main.rs` (5564 lines) into `crates/attacks/` sub-crate | XL (5-7d) | Every new WS above adds 200-500 lines to main.rs. Split first or drown. |
| arch-1 | Extract `cli/src/adcs_relay.rs` → new `icedracon/adcs-relay` crate (dual-use: ADCS admin tooling could reuse) | M (2-3d) | Follows the dual-use extraction rule. Sibling of existing `ntlm-relay`. |
| ux-0 | `SmbAuth` / `LdapAuth` / `OptAuth` shape-family flatten across ~20 subcommand Args | M (2-3d) | Removes ~300 LOC duplication. Adds `--nt-hash` to every subcommand for free (currently only 4). |
| ux-2 | Unified `--target` selector (SID / sAMAccountName / DN auto-detect) via shared `resolve_target()` | S (1d) | Removes 3× duplicated resolver logic. |
| ux-7 | Grouped interactive menu (Recon / Creds / Lateral / Persist categories) | M (2d) | Currently a 20-item flat list. UX pain point in demos. |

**Tier 3 — cross-cutting** (touch across the workstream boundary):

- Update `docs/BENCHMARKS.md` after each new primitive lands (before-vs-after on the added attack).
- CHANGELOG.md running entry — write from `git log`, never from memory (rule from 1.3.9 lesson).
- Live-validation matrix note in every WS ship checklist — 2022 + 2025 DCs (both already exist and are current per memory testlab creds).

## Cut / deferred (do NOT do in 1.4.1)

- **No Entra ID / hybrid AD / AD FS / Azure work.** Permanent scope exclusion.
- **No new sibling protocol crates** unless the dual-use rule is met.
- **No cross-forest DC lab spin-up for 1.4.1** — WS-3 ships against existing single-forest with `--foreign-sid` accepted as CLI arg; positive live-validation deferred to 1.4.2 WS-E (legacy DC matrix + trust spin-up).
- **No launch material rebuild** — the 1.3.10 rebrand is fresh, reuse the wordmark/palette/tokens as-is.
- **No arch-0 first** if you don't feel like a week of refactoring — pivot to WS-3 (small) or WS-5 (medium) to keep momentum; arch-0 can slot at any point in the cycle since it's a pure refactor.

## Suggested day-1 sequence

Pick one starter, ordered by risk-vs-payoff:

1. **Easiest starter — WS-3 cross-forest flags** (2-3 days, mostly CLI + one function in `crates/kerberos`). Adds `--foreign-sid` + `--allow-cross-trust` flags to `attack golden` and `attack constrained`. Low blast radius, shippable independently, gives a small user-visible win to unblock the release-note story.
2. **Highest payoff — WS-1 MSSQL** (3-4 days). Existing `ms-tds` crate (published, 35+ dl) has the offline TDS wire; new `attack mssql --host --user --password --kerberos --query …` builds the auth + xp_cmdshell + impersonate flow. Live-test needs an MSSQL Express install on the 2025 DC (~30 min setup).
3. **Biggest architectural bet — arch-0** (5-7 days). Splitting main.rs into `crates/attacks/` is a week of mechanical work, then every new WS above lands cleaner. Do this if you want to sink one focused week into hygiene before the feature-heavy stretch.

## Blockers to unblock this week

- [ ] Confirm CI green after 1.3.10 push (last check: MSRV bump to 1.86 in flight, docs push queued behind it). Should land any moment.
- [ ] MSSQL Express install on 2025server1 for WS-1 live-testing. `Invoke-WebRequest` install script from Microsoft, ~30 min.
- [ ] Decide: WS-3 first (fast momentum) or arch-0 first (hygiene bet)? Only one at a time.

## Success gates for 1.4.1 ship

- All 5 WS live-validated on 2022 + 2025 DCs
- Workspace `cargo test` + `clippy -D warnings` + MSRV verify green
- CHANGELOG.md 1.4.1 section written from `git log 1.3.10..HEAD`
- No new sibling protocol crates unless dual-use justified
- Site copy refresh if any new positioning phrase applies (probably a new tagline for the "grand" release — brainstorm at cut time)

## Risks to watch

- **WS-4 Kerberos sealed bind** — canonical rabbit hole. Cap at 6 days total; if it doesn't fit, defer to 1.4.2.
- **WS-2 DCShadow push** — DRSUAPI has 3 REQ versions (V2/V3/V4); need version-detect from DrsBind reply. Server 2025 may reject V2 versions older servers accept.
- **arch-0 side-effects** — if a subcommand moves to `crates/attacks/foo.rs` and its `Args` moves too, external code importing `adhammer::CoerceArgs` breaks. Add re-exports in `main.rs` for backward compat until 1.5.0.

## Follow-on releases in the pipeline

`.agents/adhammer-1.4.2-plan.md` — noPac + Zerologon + forest-trust chain + wire hardening + `krb-listen` + legacy DC matrix.
`.agents/adhammer-future.md` — 1.4.3 (quick tactical adds) → 1.4.4 (MITM+relay) → 1.4.5 (post-DA persistence) → 1.4.6 (post-DA product pivot).

Committed local, not pushed — user directive `all local` for planning docs.
