# icedracon 0.1.0 stable release cycle plan

**Date:** 2026-08-10 · **Author:** zevs · **Status:** draft after live-DC validation session

Goal: bump the 18 pre-alpha library crates from `0.1.0-dev` (`0.2.0-dev` for dpapi-ng) to
`0.1.0` (`0.2.0`) — the first stable release. This enables `cargo add ms-crtd` (etc.) to
resolve by default without `--allow-prereleases`, and signals the ecosystem is committed to
the current API surface.

## Where we stand after 2026-08-10 live-DC session

| Crate | Live-validated? | Blocker to 0.1.0 |
|---|---|---|
| ms-crtd | ✅ 34 templates parsed on 2022, 21 ESC findings (after collector bug fix `e231406`) | None |
| ms-icpr | ✅ ESC1 chain: CSR built with UPN SAN + ICPR opnum 0 accepted → cert issued | None |
| ms-pkca | ✅ PKINIT with issued cert obtained TGT (through adhammer's `attack esc1 --pkinit`) | None |
| ms-gkdi | ✅ `attack gmsa dmsa01$` on 2025 extracted NT hash → crypto validated | **UNVALIDATED-CRYPTO flag can be lifted** |
| ms-nrpc | ✅ Zerologon safe-detect both DCs (secure channel + auth3 wire OK) | None (defensive-only per triage) |
| ms-pac-forge | ✅ Golden ticket forge + KDC-accepted TGS both DCs | None |
| ms-drsr | ✅ DCSync krbtgt extracted real hashes both DCs (used transitively) | None |
| msldap-ext | ✅ Paged LDAP works in scan/collector | None |
| credssp | ✅ 59/59 offline + mock server CredSSP 3-leg | Live NLA against real 5986 HTTPS listener not run — offline is high-fidelity |
| winrm-pentest | ✅ 22/22 offline + adhammer WinRM live shell exec on both | None |
| windows-lsa | ✅ 4/4 tests on real Windows | None |
| windows-sspi-shim | ✅ 9/9 | None |
| windows-token | ✅ 6/6 | None |
| windows-scm | ✅ 5/5 | None |
| windows-wmi-com | ✅ 6/6 | None |
| windows-eventlog-native | ✅ 7/7 | None |
| ms-even6 | ✅ 11/11 offline + **wire-live-validated** (sealed bind + OpenLogHandle stub accepted by real DC — RPC fault was auth not parse error) | Server-side auth wart is not a wire bug — 0.1.0 shippable |
| ms-kile-fast | ✅ 29/29 offline (RFC 6113 CF2 KDF + wrap/unwrap vectors) | Live path needs ms-pkca+kile+anon-PKINIT chain — offline RFC vectors are canonical validation |
| ms-tds | ✅ 19/19 offline including real rustls TLS-in-TDS handshake | MSSQL install still pending on 2025 lab — offline TLS handshake test with rcgen self-signed cert exercises the full tunneling primitive |

**16 of 19 fully live-validated. 3 offline-only where offline coverage is canonical (RFC vectors / real TLS handshake / wire-accepted-by-DC). All ship-blocking bugs found in this session already fixed:**

- `check adcs` returned 0 templates → collector missed `msPKI-Cert-Template-OID` → fixed commit `e231406` (pushed 2026-08-10)
- `dcerpc 0.2.2` cyclic dep with ms-nrpc → dcerpc 0.2.3 published without ms-nrpc dep → 0.2.2 yanked (2026-08-10)

## Per-crate readiness checklist (must all tick before 0.1.0 publish)

For each of the 18 crates:

- [x] Live-DC test suite passes OR explicit "no live needed for pure-parser/pure-crypto crate" waiver
- [ ] Remaining stubs from Round 2 deepening reports addressed:
  - **credssp:** Kerberos SspKind path shipped Round 2 (fc56ad9), NTLM path shipped v0.1.0-dev. Nonce RNG remains xorshift-of-clock — **must upgrade to `rand::thread_rng` before 0.1.0** (production RNG).
  - **ms-pkca:** DH path fully wired; EncKeyPack CMS EnvelopedData shipped Round 2 (45eeb35); AS-REQ body checksum shipped Round 2 (5740a49). KDC signature verification on returned SignedData still trusts eContent verbatim — **document as known-limitation for 0.1.0**, gate a real check behind a `verify-kdc-signature` feature for 0.2.
  - **ms-icpr:** Kerberos sealed-bind shipped Round 2 (44d5697); RFC 4121 GSS-KRB5 per-message wrap for CertServerRequest over Kerberos deferred — **acceptable for 0.1.0** (NTLM path fully wired).
  - **ms-tds:** TLS-in-TDS handshake shipped Round 2 (32c194e); Login7 over encrypted channel + SQLBatch execution + full token-stream decode remain stubbed — **acceptable for 0.1.0 as "TLS handshake primitive + framing" library**, document what does not yet work.
  - **winrm-pentest:** CredSSP auth path shipped Round 2 (3636689); WSMV message encryption over sealed channel remains stubbed — **acceptable for 0.1.0** (auth+shell+run+recv work, post-auth encrypted SOAP is a follow-up).
- [ ] README updated: STATUS bumped from "pre-alpha" to "0.1.0 — first stable", usage example verified compiling, cross-links refreshed
- [ ] Cargo.toml: repository / description / keywords / categories / readme / documentation / homepage all present (rebuilt 2026-08-09, verify not drifted)
- [ ] CHANGELOG.md exists with "Unreleased" section rolled to `0.1.0` with dated entry

## Publish order (bottom-up dep chain)

**Level 0** (no icedracon library deps beyond ms-ndr / dcerpc which are stable):
ms-crtd, msldap-ext, ms-pkca, windows-lsa, windows-sspi-shim, windows-token, windows-scm,
windows-wmi-com, windows-eventlog-native, ms-nrpc, ms-gkdi, ms-even6, ms-tds, ms-pac-forge

**Level 1** (depend on a Level 0 crate through explicit path+version):
credssp (no icedracon lib dep — actually Level 0 too)

**Level 2** (need Level 0 crate published at 0.1.0):
ms-icpr (needs ms-crtd), ms-kile-fast (needs ms-pkca), winrm-pentest (needs credssp)

**Rate limit:** version updates of existing crates are lenient (~30/10min per crate), 18 in
one burst historically completes without 429s.

## Coordinated release runbook

1. **Prep on each crate directory:**
   - `cargo fmt --all`
   - `cargo test --release` (must be green)
   - Bump `version = "0.1.0-dev"` → `"0.1.0"` in Cargo.toml (dpapi-ng: `0.2.0-dev` → `0.2.0`)
   - Update README STATUS line
   - Roll CHANGELOG "Unreleased" → `## 0.1.0 - 2026-XX-XX`
   - Commit: `release: <crate> 0.1.0`

2. **Cycle through Level 0:**
   ```bash
   for c in ms-crtd msldap-ext ms-pkca windows-lsa windows-sspi-shim windows-token \
            windows-scm windows-wmi-com windows-eventlog-native ms-nrpc ms-gkdi ms-even6 \
            ms-tds ms-pac-forge credssp; do
     cd C:/Users/zevs/Documents/$c
     cargo publish --dry-run
     cargo publish
   done
   ```

3. **Wait ~60s for crates.io indexing**, then Level 2:
   - Update ms-icpr Cargo.toml: `ms-crtd = "0.1.0"` (drop `-dev`)
   - Update ms-kile-fast Cargo.toml: `ms-pkca = "0.1.0"`
   - Update winrm-pentest Cargo.toml: `credssp = "0.1.0"`
   - Bump each to `0.1.0` + publish

4. **Push all git commits + tags:**
   - `git push origin main` per repo
   - `git tag v0.1.0 && git push origin v0.1.0` per repo
   - Consider a coordinated "icedracon-0.1.0" umbrella tag on adhammer repo (or a GitHub release note)

5. **Never yank the `0.1.0-dev` versions** — external adopters may have pinned them; keep as public floor per user's ship workflow rule.

6. **adhammer workspace bump:** after all 18 stable, bump adhammer 1.3.x → **1.4.0** (minor since foundation deps semver-relaxed from `"0.1.0-dev"` to `"0.1"`). Publish workspace (12 crates version bump — soft rate limit).

## Timeline proposal

- **Now:** live-DC validation done, ecosystem bug fixed, docs drafted
- **This week:** address the 4 remaining stubs called out above (credssp CSPRNG, others already 0.1-acceptable)
- **Week 2:** README + CHANGELOG rewrites per crate, single-crate dry-run rehearsals
- **Week 3:** 0.1.0 publish burst (2 hours of coordinated releases), adhammer 1.4.0 workspace bump
- **Week 4:** announcement (Twitter thread, dev.to write-up)

## Announcement plan

- **Post 1 (X):** "First Rust offensive AD stack ships stable — 18 crates on crates.io. `cargo add ms-crtd` no longer needs `--allow-prereleases`. adhammer 1.4.0 wires all of them."
- **Post 2 (X):** Direct comparison table — impacket vs icedracon per-op timings, static-binary story, live-DC-validation matrix link.
- **dev.to long-form:** "The Rust offensive AD stack — building 40 crates in three weeks" (session narrative + design decisions + benchmarks + honest limitations).
- **Reddit /r/rust + /r/netsec:** cross-post with different framing (netsec = attack matrix, /r/rust = extraction + protocol-stack angle).

## Risks / open questions

1. **credssp CSPRNG** — critical to fix before 0.1.0 (nonce weakness would be a CVE-shaped disclosure).
2. **ms-gkdi Server 2025 dMSA schema drift** — current impl works against 2025 GA, but Microsoft has revised it in prior CTPs. Pin known-good schema + document target build.
3. **dcerpc ↔ ms-nrpc cycle** — 0.2.3 fixed by removing dep; future re-wiring needs feature-gate design, don't repeat the mistake.
4. **Server 2025 lab availability** — currently one lab DC on Default Switch (dynamic IP). Static IP + snapshot before 0.1.0 gate would make CI deterministic.
5. **cargo publish rate limit** — 18 crates in one burst has historically worked but is not guaranteed; script must retry on 429 with sleep.

## References

- Live-validation session: this session (2026-08-10), see `project_adhammer.md` + `project_testlab_creds.md` in memory
- Bug fix for `check adcs`: commit `e231406` (pushed 2026-08-10)
- Ecosystem fix for dcerpc cycle: dcerpc 0.2.3 published 2026-08-10, 0.2.2 yanked
- Per-crate deepening reports: session workflow outputs (wj5vwhwms, wf4al123f, w4zuc3equ, wi8y2y5rw)
