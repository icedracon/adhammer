# API stability — icedracon crate tiers

Each sibling crate below is placed into one of three stability tiers.
Downstream consumers should read this before pinning.

- **Tier 1 (candidate-stable).** API changes are additive only. Breaking
  changes require a major version bump *and* a deprecation cycle of at
  least one minor release. 1.0-cut candidates.
- **Tier 2 (evolving).** 0.x with active minor-version churn. Breaking
  changes are called out in the crate's own CHANGELOG. Downstream should
  pin the exact minor (`^0.2`, not `>=0.2`).
- **Tier 3 (application-shaped).** Published for the workspace's own
  needs; the API is not designed for external composition yet.
  Downstream that depends on these is signing up for future breakage.

## Bottom-of-stack (Tier 1 candidates)

| Crate | Current | Tier | Notes |
|---|---|---|---|
| `windows-sddl` | 0.1.2 | 1 (candidate-stable) | Parse + emit SDDL. Fuzz-tested. 1.0 cut planned for 1.5.0. |
| `ad-acl` | 0.1 | 1 (candidate-stable) | AD ACL bit interpretation. 1.0 cut planned for 1.5.0. |
| `ccache-io` | latest | 1 | MIT ccache codec. |
| `win32-min` | 0.1 | 1 | Minimal Windows FFI shim used across the ecosystem. |

## Protocol layer (Tier 2, evolving)

| Crate | Current | Tier | Notes |
|---|---|---|---|
| `ntlmssp` | 0.1 | 2 | NTLMSSP messages + MS-NLMP seal. Pin `^0.1`. |
| `smb2-client` | 0.2 | 2 | SMB2 client + limited server (for relay). Pin `^0.2`. |
| `dcerpc` | 0.2.8 | 2 | DCE/RPC bind-sealed. Watch for 0.3.0 breaking. |
| `ms-ndr` | latest | 2 | NDR (not NDR64). |

## MS-\* wrappers (Tier 3, application-shaped)

| Crate | Current | Tier | Notes |
|---|---|---|---|
| `ms-crtd` | 0.1 | 3 | ADCS template parser + ESC rule pack. |
| `ms-icpr` | 0.1.2 | 3 | ICPR CSR builder + wire client. |
| `ms-gkdi` | 0.1 | 3 | Crypto unvalidated; ADhammer exposes it only with `experimental-gkdi`. |
| `ms-drsr` | 0.2 | 3 | DRSUAPI. |
| `ms-tds` | 0.1.1 | 3 | MSSQL TDS 7.4 client; opt-in `mssql`, live validation owed. |
| `ms-pac-forge` | latest | 3 | PAC forgery. |
| `ms-bkrp` | latest | 3 | BackupKey Remote Protocol. |
| `ms-scmr` | latest | 3 | Service Control Manager RPC. |
| `ms-tsch` | latest | 3 | Task Scheduler RPC. |
| `ms-coerce` | latest | 3 | MS-EFSR / MS-RPRN / MS-DFSNM coercion senders. |
| `ms-pkca` | latest | 3 | PKINIT PA-PK-AS-REQ builder. |
| `ms-xcep` | latest | 3 | CEP enrollment policy. |
| `ms-pac` | latest | 3 | PAC struct + verify. |
| `ms-bkrp` | latest | 3 | BackupKey RPC. |
| `ese-parser` | 0.1 | 3 | ESE (Jet Blue) file reader. v0.2 (row decode) planned for 1.5.0. |
| `dpapi-ng` | 0.1 | 3 | DPAPI-NG (LAPS-v2 / gMSA blob decrypt). |
| `dpapi-offline` | 0.1.2 | 3 | Classic-DPAPI masterkey + blob decrypt. |

## adhammer-\* workspace crates (Tier 3, application-shaped)

Every crate under `crates/` in this workspace is Tier 3 — they exist to
compose the `adhammer` binary. Downstream is welcome to depend on them,
but the API is not stability-guaranteed until the WS-CLI-SHRINK work in
1.5.0 lands and `adhammer-sdk` / `adhammer-lib` gets a proper library
surface.

## What "tier" actually gates

- Bug-fix (patch bump) — no restrictions.
- Additive change (minor bump) — allowed in all tiers.
- Breaking change (major bump) — allowed in Tier 2 & 3 with a note in
  CHANGELOG. Restricted in Tier 1 to one-per-year and only with a
  documented deprecation cycle.
- Yank — allowed in all tiers on a real reason (credential leak, wrong
  key, broken build). Never as a "trolling" undo.
