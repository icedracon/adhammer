# ADhammer 1.4.8 — plan

**Draft, 2026-08-29.** Priority order below is by unblock-EV, not by lines of
code. Each item names the concrete blocker it removes or the concrete surface
it advances. Nothing here is a promise — the ledger of what actually lands
lives in `CHANGELOG.md` when the release ships.

## Tier 1 — release-blocking-quality items

### WS-4-P2-CLOSE — Kerberos-sealed DCE-RPC REQUEST wrap-token layout

`check krb-seal` reaches BIND_ACK byte-correct against Windows Server 2025
today; the sealed REQUEST leg still faults `SMB2 status 0xC00000AE
(STATUS_PIPE_BUSY)` on the first opnum. Every wrap-token permutation tried in
1.4.7 produces the identical fault — DC's SMB-layer response is binary
(accept/reject) with no informational discrimination, so blind hypothesis
search converges to nothing. **Closure needs a Windows-native → DC Wireshark
capture over `\PIPE\lsarpc` under Kerberos-sealed to byte-diff against our
sealer output.**

Two capture paths, both real, both requiring a domain-joined Windows client
authenticated as a domain user (Kerberos LSA context is initialised at login):

1. **Interactive RDP to the domain-joined test client** — `pktmon` capture on
   ports 445 + 88, converted to pcapng, moved back for `tshark` decode.
2. **`sshpass`-driven remote invocation of the same pipeline** on the same
   client (Kerberos LSA still comes from a real domain login, not the SSH
   session). Untested end-to-end so far.

Once the reference capture is in hand, iterate the sealer against the
byte-diff, ship the fix, unhide `check krb-seal`, drop `[SCAFFOLDING]`.

### WS-D1 + WS-D2 — real `ms-dcom` + `ms-wmi` fills

Both currently scaffolds. Gated on WS-4-P2-CLOSE (need a working sealed
REQUEST layer before either DCOM activation or WMI query round-trips work
against Server 2025). Land in the same wave.

### WS-WIRE-TRACE — instrument dcerpc / smb2-client / ntlmssp

1.4.7's WS-KRB-TRACE landed on `adhammer-kerberos` because we own it and no
dep-chain dance was needed. Wire-layer per-PDU tracing for the transport
crates (`dcerpc`, `smb2-client`, `ntlmssp`) is the honestly-promised
completion of the `-vvv` UX. **Requires a fresh patch bump of each upstream
crate + a cascade through everything that pins them.** Same redaction
discipline as WS-KRB-TRACE: identifier strings + byte counts + sequence
numbers + opnums only, never body payloads or secrets.

## Tier 2 — user-visible friction

### WS-DEFENDER-SIGN — Windows Defender false-positive on install

Live-verified 2026-08-29: `cargo install adhammer` on a fresh Windows box
gets the built `adhammer.exe` quarantined with `os error 225` ("file contains
a virus or potentially unwanted software"). WS-DEFENDER-DOC in the 1.4.7
README documents the PowerShell exclusion workaround, but the friction is
real and every new Windows user hits it once. Two candidate fixes:

1. **Code-sign the release binary.** Buy an Extended-Validation code-signing
   cert (~$300/year), sign the release artifact in CI, publish the signed
   binary as a GitHub Release attachment. Public consumers `curl -L`
   the signed exe instead of building from source.
2. **Submit adhammer as a `false positive` to Microsoft.** Free but slow
   (weeks-to-months of triage) and only covers one specific hash — the next
   build gets quarantined again unless we keep re-submitting.

Path 1 gives users a clean install today; path 2 doesn't scale. Both viable.

### WS-CLEAN-LIVE — 0-vuln banner live-render

The green **hardened-bill-of-health** banner ships in 1.4.7 and is
unit-tested (`clean_bill_reports_no_findings`), but we've never live-rendered
it against a real DC — every lab target has seeded findings. Two options:

1. **Stand up a genuinely-hardened Server 2025 DC** without the
   `adhammer_lab_seed` vulnerabilities. Expensive but the right long-term
   test target.
2. **Add `adhammer scan --only <check-ids>` filter** so an operator can
   deliberately run only checks known-clean on the current DC and reproduce
   the assurance-banner render. Ships the diagnostic surface without needing
   a second DC.

Path 2 is cheaper + ships in this release; path 1 is a follow-up.

### WS-INT-STAGE-CHECK — rich stages on `check` verbs

Every `attack` verb wraps its impl in a `run_action_with_brief` StageChecklist
per 1.4.6. `check` verbs (`check adcs`, `check krb-seal`) still print raw
finding lines with no per-stage narration. Consistency win — same UX shape
across the CLI surface.

## Tier 3 — ecosystem adopter sweeps

### WS-WIN32-MIN-ADOPT — use the icedracon Windows-* wave

The 2026-08-29 wave shipped `win32-min` 0.1.3, `windows-token`, `windows-scm`,
`windows-lsa`, `windows-eventlog-native` all at 0.2.1. None are in ADhammer's
dep tree yet (memory previously called win32-min "the default Windows FFI"
but that's aspirational). Adopting them where ADhammer currently uses
raw kernel32 FFI or the `windows-rs` monster would cut compile time and give
the ecosystem its first real downstream consumer.

Candidate sites: `cli/src/main.rs::enable_windows_console` (kernel32 direct
FFI, migrate to `win32-min`), any COM interaction that currently uses
`windows-rs`, and the report crate's audit-log surfaces.

### WS-COVERAGE-70 — lab seed 50→70%

50% coverage plateau today (29/58 tripped). Remaining 29 clean split:
- 5 trust (external forest — needs a second seeded forest to reach)
- 12 ESC cert-template (needs CA-publish + `certutil edittemplate` seed)
- 7 stale/dormant (SAM-protected attrs; needs `lastLogon` timestamp
  backdating via `ldapmodify` on the DC)
- ~5 seedable with more investigation

Each seed adds a real live-verified finding to the coverage matrix.

## What 1.4.8 is NOT

Not a place for greenfield checks, new report formats, new attack verbs, or
scope expansion beyond fixing the honest gaps 1.4.7 documented. Every item
above is a specific known-open thing — not "more of everything."
