# Session state snapshot — 2026-08-23 (mid-1.4.1 stretch)

Written mid-session in case network drops. All work below is **on-disk locally** — no push, no publish. Agent subprocesses run locally so an internet drop doesn't kill them.

## adhammer (main branch — LOCAL commits ahead of origin)

`git log --oneline -12` at snapshot time:

```
b5c3950 WS-1 (1.4.1): attack mssql — TDS 7.4 client + xp_cmdshell + EXECUTE AS chain
1bdcf6b WS-2 (1.4.1): DCShadow via DRSUAPI — modern-Windows path
7798d90 WS-5 (1.4.1): DACL Attacks II — 5 new abuse actions + --dry-run
be886a5 WS-3 (1.4.1): --foreign-sid on attack golden for cross-forest golden tickets
e5203bb ux-7: grouped interactive menu (Recon / Creds / Lateral / Persist / Session)
2ec7b78 ux-2: unified --target classifier + resolver helpers
f47d4d5 ux-0: shape-family shared Args (SmbAuth / LdapAuth / OptAuth)
a68f637 arch-1: move cli/src/adcs_relay.rs -> cli/src/attacks/adcs_relay.rs
feaa03d arch-0 (batch 4 — FINAL): extract enum/dump/check/roast/scan into subtrees
e2af597 arch-0 (batch 3): extract 7 large attack handlers + dispatch groups
26ce550 arch-0 (batch 2): extract 10 mid-size attack handlers
2ff0062 arch-0 (batch 1b): extract 5 more attack handlers
```

`main` on `origin/main` = `a68f637` (arch-1) — everything from ux-0 forward is **local-only**, per the "1.4.1 stays local" directive.

Untracked (harmless — planning docs + site + patches, none critical): `.agents/*.md`, `.github/workflows/pages.yml`, `docs/social-1.3.9.png`, `patches/`, `site/`, `.playwright-cli/`.

## Sibling crate state

- **ms-pac-forge** — 5f1904c local (0.1.3, WS-3 ExtraSids), unpublished
- **ms-drsr** — d765d05 local (0.2.0, WS-2 opnums 17+5), unpublished
- **ms-tds** — 5dffba8 local (0.1.1, WS-1 run_query/impersonate/revert), unpublished
- **dcerpc** — WS-4 agent still running; uncommitted changes to CHANGELOG.md, Cargo.toml, src/lib.rs, src/pdu.rs + new file src/krb_seal.rs

## `[patch.crates-io]` pins in adhammer/Cargo.toml (MUST revert before ship)

```
ms-pac-forge = { path = "../ms-pac-forge" }
ms-drsr      = { path = "../ms-drsr" }
ms-tds       = { path = "../ms-tds" }
```

Plus dcerpc if WS-4 agent adds one.

## Score at snapshot

- ✅ arch-0 / arch-1 / ux-0 / ux-2 / ux-7 — refactor pack, all pushed to origin
- ✅ WS-3 cross-forest `--foreign-sid` — local, offline+CLI complete
- ✅ WS-5 DACL Attacks II — local, offline+CLI complete, live-`--dry-run` verified on DC01
- ⚠️ WS-2 DCShadow modern — local, Phase 1+2 complete, Phase 3 live-push deferred
- ⚠️ WS-1 MSSQL — local, Phase 1+2 complete, Phase 3 live-query deferred (needs MSSQL Express install on 2025server1)
- ⏳ WS-4 Kerberos sealed bind — agent in flight at snapshot time

## Live-test baseline (from Saturday, both DCs reachable)

- **DC01 (2025)** — 172.29.247.82 / 192.168.91.20 — `TESTLAB\Administrator:Zikurat2003$`
- **2022server** — 172.29.255.68 / 192.168.0.52 — `TESTLAB\Administrator:TestPass2026!`

krbtgt hashes captured earlier this session — DC01 NT `1a9037d7160bf3c935f3cd91d8ac9419` / AES256 `e47862d1...c2f96`, 2022 NT `332073b01716bcff9cef1b6b6ef28ba8` / AES256 `e0bc1c72...9c681`.

## Deferred to next interactive session

- WS-2 Phase 3 — live DCShadow push against 2019+/2022/2025 DC (pick benign attribute, capture original, verify readback)
- WS-1 Phase 3 — MSSQL Express install on 2025server1 (Microsoft one-liner), then live smoke tests
- WS-4 Phase 2 (if not done by agent) — live Kerberos sealed bind against DC01 samr/dcsync
- WS-3 cross-forest positive validation — needs a two-forest trust (1.4.2 WS-E scope)
- Coordinated batch publish for 1.4.1 ship: strip `[patch.crates-io]` → publish ms-pac-forge 0.1.3 + ms-drsr 0.2.0 + ms-tds 0.1.1 (+ dcerpc if bumped) → bump adhammer 1.3.10 → 1.4.1 → publish → tag → push
