> **Superseded by [docs/PLAN_1.5.0.md](PLAN_1.5.0.md).** Kept in-tree
> for its 5 framing principles (start-from-scope, consent gates,
> low-impact-first, reuse-authed-stack-only-when-prereqs-met, evidence-
> over-guaranteed-DA) which the canonical plan now carries. This
> document's "Already implemented locally" claim in §0 was aspirational
> — verified 2026-09-02 that `scope.rs` / `discovery.rs` / `blackbox.rs`
> are untracked and not compiled; see canonical plan §"Verified code-
> state audit" and `WS-FOUNDATION-INTEGRATE`.

---

# ADhammer 1.5.0 research plan - no-cred assessment, dependency strategy, and crate ownership

Written 2026-09-01 after the 1.4.9 publish/tag cycle completed. This
document replaces the earlier revamp draft and reframes 1.5.0 as one
release with one clear contract:

- Start from scope, not credentials.
- Run low-impact discovery first.
- Gate risky actions behind explicit operator consent.
- Reuse the 1.4.x authenticated stack only when prerequisites are
  actually met.
- Produce evidence and next-action guidance, not a guaranteed
  "no-cred to DA" story.

1.5.0 is therefore not "make AdHammer into mini-nmap + mini-nuclei +
mini-Responder." It is a bounded Active Directory assessment workflow
that starts without credentials and hands off to the existing
authenticated verbs only when the environment truly allows it.

## 0. Current local start state

1.5.0 has now started locally on 2026-09-01. The branch is no longer at
"research only"; the first foundation slice is already landed in the
working tree.

Already implemented locally:

- Starter dependencies reduced to the clean first-pass set:
  `ipnet` and `hickory-resolver`.
- `adhammer-core` now exports the first no-cred assessment control-plane
  types:
  `EngagementScope`, `ScopeTarget`, `CheckId`, `CheckClass`,
  `FindingStatus`, `Capability`, `CapabilityKind`, `NextAction`,
  `SecretHandle`, `ScopeError`.
- `adhammer-sdk` now exports the first runner-facing types:
  `BlackBoxRunner`, `RunPolicy`, `ConsentPolicy`, `CheckSelection`,
  `RunSummary`.
- Scope JSON round-trip, include/exclude logic, hostname normalization,
  check-id validation, and runner policy gating all have tests.
- The full workspace currently passes `cargo test --workspace
  --all-targets` and `cargo clippy --workspace --all-targets -- -D
  warnings` with this foundation in place.

What this means:

- 1.5.0 is now in an active local implementation phase.
- The next work is not "pick starter deps" anymore.
- The next work is "consume the new model in collector and the SDK
  runner."

## 1. Release contract

The 1.5.0 contract is:

1. Accept a machine-readable engagement scope.
2. Discover AD-relevant hosts and services from that scope.
3. Run low-impact no-cred checks that are useful on modern networks and
   still cleanly report when blocked by hardening.
4. Offer consent-gated impact actions with explicit blast-radius text.
5. Chain into existing authenticated functionality only after a real
   credential, ticket, certificate, or machine-account capability is
   obtained.
6. Emit a report where every finding has provenance, evidence, and a
   standalone rerun command.

The release does **not** promise Domain Admin. It promises accurate
enumeration, trustworthy evidence, correct prerequisite checks, and a
coherent operator workflow.

## 2. Terms and boundaries

The old draft used "passive" too loosely. For 1.5.0 we should use these
terms consistently:

- `low-impact discovery`: network activity that touches targets but does
  not attempt authentication, state change, or service coercion.
- `consent-gated action`: activity with lockout risk, alerting risk,
  spoofing/relay risk, or possible state change.
- `post-cred escalation`: existing 1.4.x authenticated workflows that
  become available only after a real capability is obtained.

Hard boundaries:

- No guarantee of credential capture or privilege escalation.
- No default plaintext credential persistence to disk.
- No automatic "machine account implies DCSync" shortcut.
- No broad generic web fuzzing, nuclei-like vuln scanning, or
  internet-scale port scanning.
- No attempt to compete with external OSINT, masscan, or general web
  scanners.

## 3. Architecture decision

The earlier draft put almost everything into new CLI modules. After
reviewing the 1.4.9 tree, that is the wrong long-term shape.

1.5.0 should keep the CLI thin and move the orchestration into existing
library crates:

| Crate | 1.5.0 role |
| --- | --- |
| `adhammer-core` | engagement scope, check ids, evidence types, capability state, redacted references |
| `adhammer-sdk` | black-box runner, phase sequencing, consent policy, result aggregation |
| `adhammer-collector` | target discovery, network probes, LDAP collection glue |
| `adhammer-kerberos` | AS-REQ user enum, AS-REP roast, etype probe, PKINIT probe |
| `adhammer-sysvol` | anonymous SYSVOL/GPP parsing and extraction |
| `adhammer-report` | human report plus machine-readable evidence bundle |
| `adhammer` CLI | argument parsing, prompt UX, stdout/stderr rendering, output file wiring |

Decision:

- No new sibling crate is required to start 1.5.0.
- New reusable library surfaces **are** required inside the existing
  crates.
- If a discovery layer becomes large enough to have more than one real
  consumer after 1.5.0, then carve it out later. Do not pre-split now.

## 4. Core implementation model

Treat the full vector map as `check ids`, not as dozens of independent
top-level commands.

Recommended shape:

- One orchestrator command:
  `adhammer black-box --scope scope.json --out engagement.md`
- Optional selection flags:
  `--only`, `--skip`, `--allow-impact`, `--allow-spoof`, `--max-hosts`,
  `--max-duration`, `--evidence-bundle`, `--save-secrets=<off|vault>`
- Internal representation:
  `CheckId`, `CheckClass`, `Prerequisite`, `Evidence`, `Finding`,
  `Capability`, `NextAction`

Each check returns one of:

- `found`
- `not_found`
- `blocked`
- `not_applicable`
- `error`

That matters because many enterprise networks will block anonymous LDAP,
null session RPC, AXFR, or relay paths. A blocked result is not failure;
it is evidence of hardening.

## 5. Vector map to implementation modules

The user-supplied map is good, but it should collapse into a smaller set
of implementation modules.

| Module | Check ids owned here | Notes |
| --- | --- | --- |
| `discovery::dns` | `dns-enum`, `nsec-walk` | standard DNS, SRV/PTR/A, optional AXFR/NSEC |
| `discovery::mdns_nbns` | `mdns-enum`, `nbtns-enum` | multicast/broadcast discovery and NBSTAT |
| `discovery::ports` | `port-sweep`, `service-fingerprint`, `tls-cert-scrape` | targeted AD service discovery, not general internet scan |
| `discovery::hostmeta` | `arp-sweep`, limited host metadata | platform-sensitive, interface-aware |
| `discovery::http` | `web-fingerprint`, `xcep-ndes-probe`, optional `ntlm-http-enum`, optional `owa-user-enum-timing` | AD-adjacent HTTP only |
| `ldap::anonymous` | `ldap-rootdse`, `ldap-anon-enum`, `ldap-anon-policy`, `ldap-anon-trusts`, `adidns-anon`, existing anonymous ADCS | one subtree, one policy surface, one evidence model |
| `kerberos::preauth` | `kerbrute`, `asrep-roast`, `krb-etype-probe`, `krb-pkinit-probe` | extends existing Kerberos stack cleanly |
| `smb::anonymous` | `smb-null-bind`, `smb-shares-anon`, `smb-sysvol-harvest` | negotiate, IPC$, share traversal, GPP harvest |
| `rpc::anonymous` | `samr-null-enum`, `lsat-null-enum`, `srvsvc-null-enum`, `wkssvc-null-enum`, `rrp-null-enum`, `msrpc-endpoint-map` | depends on sibling RPC/SMB libraries being stable enough |
| `detect::nocred` | `zerologon --detect`, `smbghost-detect`, `eternalblue-detect`, `ntlm-drop-signing-detect` | strict probe budget, no write path here |
| `impact::spray` | `spray --kerberos`, `--ldap`, `--smb`, `--winrm`, `--mssql` | one policy gate, per-protocol adapters |
| `impact::poison` | `poison-llmnr`, `poison-nbtns`, `poison-mdns`, `poison-wpad`, `poison-dhcpv6` | strongest runtime gate and interface rules |
| `impact::coerce` | `coerce --scan-all`, `nopac` candidate routing | only after explicit authorization |

Important corrections:

- `os-fingerprint` should not be a headline feature for 1.5.0. Replace
  it with protocol-observed host characterization.
- `owa-user-enum-timing` is fragile and noisy. Keep it optional and
  disabled by default.
- `nopac` is not a no-cred primitive. It belongs to capability-gated
  post-cred logic.

## 6. Dependency research as of 2026-09-01

The right question is not "can a crate be found" but "does adding it
reduce risk and code size enough to justify the dependency surface."

### 6.1 Add now

| Crate | Latest checked version | Decision | Why |
| --- | --- | --- | --- |
| `ipnet` | `2.12.1` | added locally | Scope parsing, CIDR math, host containment, report rendering; extremely mature and already common across the Rust ecosystem |
| `hickory-resolver` | `0.26.1` | added locally | Clean SRV/A/PTR lookup path, Rust 1.88 compatible, strong maintenance, avoids home-grown resolver logic |
| `socket2` | `0.6.5` | defer until used | Already common in the tree transitively; only add as a direct dep if a module truly needs raw socket configuration |

### 6.2 Add only if the corresponding vector stays in scope

| Crate | Latest checked version | Decision | Why |
| --- | --- | --- | --- |
| `hickory-proto` | `0.26.1` | add if AXFR/NSEC packet-level work is implemented | Lower-level DNS protocol layer is useful once the resolver surface is not enough |
| `mdns-sd` | `0.21.1` | add if `mdns-enum` stays | Maintained, runtime-light, no async-runtime requirement by default, better than writing mDNS service discovery from scratch |
| `netdev` | `0.46.2` | add if ARP/poison modules need interface metadata | Cross-platform interface enumeration is the real value, not packet send/receive |
| `snmp2` | `0.5.2` | add if SNMP is kept as a first-class check | Recent, actively updated, real client library; better choice than thin parser-only crates |
| `dhcproto` | `0.15.0` | add if DHCPv6 spoofing remains in 1.5.0 | Proper DHCPv4/v6 encoding/decoding without inventing your own packet parser |
| `pcap-file` | `2.0.0` stable line | dev-only add if packet fixtures become part of tests | Good for offline fixture capture/replay, not needed in runtime path |

### 6.3 Evaluated and not recommended for 1.5.0

| Crate | Checked version | Decision | Reason |
| --- | --- | --- | --- |
| `pnet` | `0.35.0` | do not add | Large low-level surface for too little benefit; stale compared with lighter targeted options |
| `arp-scan` | `0.15.1` latest, `cargo info` pulled `0.14.0` | do not add | AGPL licensing is a non-starter for this repo and the runtime value is narrow |
| `rsnmp` | `0.1.0` | do not add | Marked WIP and too small a maturity signal for core runtime use |
| `domain` | `0.12.2` | do not add now | Solid DNS library, but Hickory is the cleaner fit for the resolver-first use case |
| `socket2 = 0.5` | obsolete line | do not use | Current stable line is `0.6.5`; the old draft's version is outdated |

### 6.4 Cases where the right answer is "write the module ourselves"

There are several vectors where a new dependency is less appealing than
small internal code on top of AdHammer's existing stack:

- `NBSTAT` / NetBIOS name service query and parse:
  a small local packet encoder/decoder is acceptable.
- `NTLM HTTP enum`:
  implement on top of the existing NTLM stack and a tiny HTTP client
  path instead of importing a specialized enum crate.
- `smbghost-detect`, `eternalblue-detect`, `ntlm-drop-signing-detect`:
  these should live on top of your own SMB/NTLM libraries, not third
  party PoC crates.
- `coerce --scan-all`:
  use existing RPC transport work and unify dispatch locally.
- `PKINIT probe`:
  build on the current Kerberos code, plus your own certificate and KDC
  handling, rather than introducing a separate Kerberos client stack.

## 7. Sibling crate policy

The main architectural risk is not missing crates. It is coupling
AdHammer 1.5.0 to unpublished or drifting sibling-crate state.

Rules for 1.5.0:

1. The default branch should consume published registry releases.
2. If `adhammer` needs a new feature in `dcerpc`, `smb2-client`,
   `ms-icpr`, `ms-gkdi`, `ntlmssp`, `windows-sddl`, or another sibling,
   that sibling gets:
   - its own version bump
   - its own tests
   - its own changelog note
   - its own tag/publish decision
3. Only then does the `adhammer` workspace move to the new version.

This avoids a bad 1.5.0 where the top-level repo compiles only because
the operator happens to have half a dozen dirty sibling checkouts next
to it.

Concrete dependency policy for 1.5.0:

- Keep `windows-sddl`, `ntlmssp`, `smb2-client`, `dcerpc`, `ms-crtd`,
  `ms-icpr`, `ms-gkdi`, `ms-tds`, and `dpapi-offline` pinned to
  published versions unless a specific missing feature forces a bump.
- Do not drag in experimental sibling crates just because they exist on
  GitHub.
- Treat local dirty sibling checkouts as research material, not as
  release inputs.

## 8. Internal library work

Part of this now exists locally, and part still needs to be written.

### 8.1 `adhammer-core`

Already landed locally:

- `EngagementScope`
- `ScopeTarget`
- `CheckId`
- `CheckClass`
- `FindingStatus`
- `Capability`
- `CapabilityKind`
- `NextAction`
- `SecretHandle`
- `ScopeError`

Still needed here:

- any additional `EvidenceRef`-style indirection once report integration
  starts
- helper methods for scope-file loading and future host/service scoping
  policies

The critical design point is that reports should reference secret
material indirectly, not print or casually persist it.

### 8.2 `adhammer-sdk`

Already landed locally:

- `BlackBoxRunner`
- `RunPolicy`
- `ConsentPolicy`
- `CheckSelection`
- `RunSummary`

Still needed here:

- orchestration hooks for discovery
- report emission handoff
- post-cred capability adapters
- durable check catalog / runner registration

This crate is the right home for "one command drives many checks" logic.

### 8.3 `adhammer-collector`

Add:

- scope-driven DNS discovery built on `hickory-resolver`
- targeted port-discovery layer
- DNS resolution/ad-discovery glue
- per-host service inventory
- LDAP anonymous collection adapters
- shared timeout/retry budgets

### 8.4 `adhammer-report`

Add:

- Markdown engagement report
- JSON evidence bundle
- rerun command renderer
- machine-readable "blocked by hardening" reporting

### 8.5 `adhammer-secrets`

Add:

- memory-only secret registry for the current run
- zeroizing owned secret values
- optional future vault abstraction, but not mandatory for 1.5.0

Do not add a default `credentials.json` dump. If the operator wants
persistence later, it should be explicit, encrypted where possible, and
owned by `adhammer-secrets`.

## 9. Research-to-implementation order

One release, no milestone labels, but still a clear work order:

1. Define the result model and scope model in `adhammer-core`.
2. Add the SDK orchestration layer in `adhammer-sdk`.
3. Land the low-impact discovery modules that are mostly independent of
   privileged or fragile behavior:
   DNS, port/service fingerprinting, TLS scrape, RootDSE, Kerberos
   preauth checks, AD-adjacent web fingerprint.
4. Land anonymous/null enumeration that depends on the existing
   protocol stack:
   SMB null, RPC endpoint map, LDAP anon subtree/policy/trusts,
   SYSVOL/GPP harvest.
5. Add reporting and evidence bundle output.
6. Add consent-gated impact modules selectively:
   spray first, then spoof/coerce families only if interface and safety
   controls are already solid.
7. Integrate post-cred chaining by capability, never by assumption.

This order matters because it keeps the early work cross-platform and
testable, and it postpones the noisiest features until the engine and
evidence model already exist.

Current local status against that order:

- Step 1 is started and the base type layer is in place.
- Step 2 is started and the minimal runner policy layer is in place.
- Step 3 is the active next implementation target.

## 10. Test and verification plan

1.5.0 should not be shipped on a "full black-box to DA" acceptance
criterion. That is too environment-dependent.

Ship criteria should instead be:

- `cargo test --workspace --all-targets` green
- `cargo clippy --workspace --all-targets -- -D warnings` green
- `cargo deny check` green
- `cargo audit` green
- deterministic unit tests for each packet parser and response parser
- fixture-driven tests for DNS, SMB negotiate, RPC endpoint map, HTTP
  fingerprints, LDAP RootDSE and subtree handling
- integration receipts for:
  - hardened modern AD where many anonymous paths are blocked
  - intentionally misconfigured AD where at least some no-cred paths
    succeed
  - one environment where a valid post-cred escalation path exists

Success means:

- checks terminate cleanly
- blocked states are explained correctly
- evidence is attributed correctly
- the tool never invents capability it does not actually possess

## 11. What 1.5.0 should say "no" to

Even if the vector map is ambitious, these are the right cut lines:

- No giant CLI-only orchestrator.
- No default secret dump file.
- No "guaranteed DA" receipt as the release gate.
- No stale `socket2 0.5` pin.
- No `pnet` unless a later requirement genuinely forces it.
- No AGPL `arp-scan`.
- No dependency on unreleased sibling-crate state by accident.
- No broad web fuzzing or generic vulnerability template engine.

## 12. Bottom line

The strongest 1.5.0 is:

- one black-box assessment workflow
- one result/evidence model
- one dependency strategy with very few new crates
- a moderate amount of new internal library code
- a strict boundary between low-impact discovery, consent-gated action,
  and post-cred exploitation

Recommended new dependencies for the first implementation pass:

- `ipnet = "2.12"`
- `hickory-resolver = "0.26"`
- direct `socket2 = "0.6"` only if a module actually needs it

Conditionally justified later in the same release if the exact vectors
stay in scope and tests exist:

- `hickory-proto = "0.26"`
- `mdns-sd = "0.21"`
- `netdev = "0.46"`
- `snmp2 = "0.5"`
- `dhcproto = "0.15"`

Everything else should be written on top of the stack you already own,
or cut from 1.5.0.
