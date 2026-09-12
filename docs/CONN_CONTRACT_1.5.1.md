# ADhammer 1.5.1 — Connection / Lifecycle Contract (W151-03)

**Status:** spec. Documents the current parameter surface, timeout /
cancellation / SOCKS / TLS discipline, and names the closable gaps. No
source changes in this pass.

## 1. Shared parameter surface — current state

Three flattened auth structs in `cli/src/shared_args.rs`:

| Struct | Fields | Consumers (17 handlers total) |
|---|---|---|
| `SmbAuth`   | `--host`, `--domain`, `--user`, `--password` | abuse, coerce, dcsync, dns, esc1, esc4, exec_pack, lsa, mssql, samr, scan, secretsdump, shadowcred, winrm_exec, sessions, posture (+7 more via re-use) |
| `LdapAuth`  | `--url`, `--user`, `--password`, `--insecure`, `--allow-plaintext-ldap` (G-19) | scan, check adcs, laps, gmsa, esc_registry |
| `OptAuth`   | all four optional + `--insecure` + `--allow-plaintext-ldap` | abuse (`--action pkinit`) et al. |

**Verdict:** the ux-0 unification worked — 17 handlers share the flatten,
and G-19 (`--allow-plaintext-ldap`) landed on both LdapAuth **and** OptAuth
so no cleartext path escapes the consent gate.

**Global TCP-level knobs on top-level `Cli`:**

- `--socks5 [user:pass@]host:port` — proxy-side DNS, routes ALL outbound
  TCP. Parsed at `main.rs:654` via `smb2_client::socks::Socks5::parse`,
  installed as `smb2_client::socks::set_proxy(Some(cfg))`. Every SMB /
  RPC / raw-TCP dial in the workspace honors it. ldap3 (which owns its
  own TCP dial and can't be re-hooked) uses the local-listener rewrite
  trick at `collector/src/lib.rs:249`.
- `--json` / `--text` — mode toggles, orthogonal to auth.
- `--no-color` / NO_COLOR env — respected in ui + spinner.

Per-verb timeouts exist in **two** places today:

- `doctor` (`--timeout N`, bounds every probe **and** the classified bind).
- `blackbox / run` (`--timeout N`, per-request web fingerprint).

**Gap:** no global `--timeout` on scan/attack/enum/kerb/creds/ldap/lsa.
Each of those verbs relies on library-crate internal defaults
(`LDAP_PER_ENTRY_TIMEOUT` in `collector`, `Duration::from_secs(default)`
in various protocol crates). An operator cannot cap wall-clock time on
a run without editing source.

## 2. TLS backend inventory

**Two TLS stacks in the workspace.**

| Site | Backend | Reason |
|---|---|---|
| `cli/src/main.rs:627`             | rustls (aws-lc-rs)  | crypto provider install at startup |
| `crates/collector/src/lib.rs:182` | `native_tls`        | ldap3's own TLS backend — not swappable per ldap3 0.12 API |

Consequence: certificate-verification behavior on LDAPS goes through
native-tls (Windows: schannel, Linux/macOS: OpenSSL); every other TLS in
the tree (ADCS Web HTTP, rustls-based `attack ldap auth`, tokio-rustls
NTLM relay client) goes through rustls + aws-lc-rs.

An auditor concern about "did we verify the cert chain the way I told you
to" cannot be answered with one call chain — it depends on whether the
verb touched ldap3 (native-tls) or something else (rustls).

**`--insecure` semantics:** on `LdapAuth`/`OptAuth`, disables `native_tls`
peer verification via `TlsConnector::builder().danger_accept_invalid_certs(true)`
per collector:182 (implied). On rustls sites, `--insecure` is not always
piped through — verify per site.

## 3. Cancellation discipline

`main.rs` runs under `#[tokio::main]`. Ctrl-C is caught by tokio's default
signal handler, which sets the runtime's shutdown flag. Verbs that use
`tokio::time::timeout(...)` will terminate on the *next* await point after
signal receipt.

**Gap:** no explicit `CancellationToken` propagation. A verb mid-way
through a multi-stage flow (e.g. `attack esc1`: enroll → retrieve → PtT
→ verify) has no way to observe "user cancelled, unwind stages 2-4 with
cleanup" — the runtime just stops on the next await.

**Consequence for W151-02 (result contract):** without cancellation-aware
teardown, mid-flight Ctrl-C reports `error` today (anyhow bail from the
interrupted future) rather than `status: cancelled`.

**Proposed fix (patch-safe):** thread `tokio_util::sync::CancellationToken`
through each verb's top-level future; on `is_cancelled()`, emit
`status: cancelled` and exit 130. This is behavioural, not API — no SDK
break. Landing target: 1.5.2 or 1.6, not 1.5.1.

## 4. Retry / idempotency discipline

**Plan mandate:** "Повторы только для безопасных операций; не повторять
изменения состояния неявно."

**Current state audit** (sampled — full audit is a subtask):

| Path | Retry? | Idempotent? |
|---|---|---|
| collector LDAP search paged fetch | yes on transport error, bounded by ldap3's `conn_timeout` | yes (read) |
| DNS SRV discovery                 | yes (3 tries, hand-rolled)     | yes (read) |
| `attack abuse` LDAP write         | **no explicit retry**          | mixed — `set-primary-group` is idempotent, `add-member` is not |
| `attack coerce` MS-EFSR call      | **no explicit retry**          | yes (side-effect is coerced auth, no persistent state) |
| `attack esc1` enroll              | **no explicit retry**          | not idempotent — each enroll mints a new cert |
| `attack asktgt`                   | **no explicit retry**          | idempotent (writes a ccache, overwrite fine) |

**Verdict:** current implicit rule "no retry on state-changing operations"
holds by default (nothing retries). The gap is documentation, not code.
`docs/STABILITY.md` should assert the rule explicitly so a contributor
can't sneak a "helpful" retry into `abuse` in a future patch.

## 5. Parameter-equivalence — CLI vs menu vs SDK

**Plan mandate:** "Одинаковые настройки TLS/proxy/DNS/scope и
предварительная проверка параметров… нет неявного TLS downgrade,
зависания или расхождения настроек интерфейсов."

Current state:

| Aspect | CLI | Interactive menu | SDK |
|---|---|---|---|
| `--socks5` proxy | applied globally via top-level flag | inherited (same process) | applied globally, no per-call override |
| `--insecure` TLS | per-verb via `LdapAuth`/`OptAuth` | menu prompts for the value | per-verb config knob |
| `--allow-plaintext-ldap` | flag on `LdapAuth`/`OptAuth`, prompts consent regardless | menu prompts + consent | flag on config, prompts consent |
| Password source (@file/env/argv) | supported via `SecretString::FromStr` | interactive `rpassword`-style prompt | direct value pass |
| Bind consent (plaintext LDAP) | interactive `Confirm::new().default(false)` per collector | same code path | same code path |
| DNS resolver | hand-rolled `DnsResolver` for discovery; system resolver for connect | same | same |
| Timeout | per-verb where present; no global | inherited from CLI defaults | caller responsibility |

**Gaps:**

1. **G-3.1 — no global `--timeout`.** CLI/menu/SDK all inherit the same
   library-crate default (varies per crate). An operator with a flaky VPN
   can't cap wall-clock time end-to-end.
2. **G-3.2 — TLS-verify audit line.** `--insecure` disables server-cert
   verification silently in log output. Auditors want a stderr line like
   `warning: TLS server verification DISABLED — this run's LDAPS results
   are not authenticated`. Would land on the initial bind, once per verb.
3. **G-3.3 — SmbAuth has no `--insecure`.** SMB2 negotiates its own
   signing/sealing; there's no cert verify on the SMB path. Fine — but
   `SmbAuth` also lacks any TLS-related knob, so a mixed `attack esc1`
   invocation (LDAP + SMB + optional Kerberos) has *some* verify knob
   from LdapAuth and none from SmbAuth. Consistent-looking, actually
   correct.
4. **G-3.4 — DNS resolver inconsistency.** The hand-rolled RFC1035 client
   in `blackbox / run` uses configurable nameservers; every other verb
   uses `tokio::net::lookup_host` (system resolver). A caller who set
   `--nameservers 8.8.8.8` on `run` finds that setting is not honored
   by the follow-up `attack` verb.
5. **G-3.5 — Scope enforcement.** `crates/core/src/scope.rs` defines
   `EngagementScope`, `ScopeTarget`, `ScopeError`. Every verb that
   dispatches over the wire *should* consult it before egress. Sampled
   spot-checks show this is done in the collector but not in every
   ad-hoc dial site (e.g. `attack coerce` dial). Full audit is a subtask.

## 6. Deliberate non-goals for 1.5.1

- **Global `--timeout N` flag.** Add-on for 1.5.2. Requires threading a
  `Duration` through every verb; not a mechanical change (each protocol
  crate has its own timeout knob).
- **Cancellation-token propagation.** 1.5.2 or 1.6, per §3.
- **Uniform TLS backend.** Migrating ldap3 off native-tls is an ldap3-
  library concern (or a patched fork). Out of scope; document the split.
- **SOCKS-aware DNS-over-TCP for the hand-rolled resolver.** Would help
  the another live-DC session pattern noted in memory; owed for 1.5.2 track.
- **`--nameservers` on every verb.** As per G-3.4, this is a UX gap but
  not a security gap; deferred.

## 7. What lands in 1.5.1 for W151-03

The plan's Done statement: "нет неявного TLS downgrade, зависания или
расхождения настроек интерфейсов."

Minimum 1.5.1 acceptance:

- [ ] Documentation of the SOCKS5 pivot semantics in `docs/STABILITY.md`
      (which verbs honor it, which don't — none don't today, but
      library-crate rewrite trick used by ldap3 needs an explanation).
- [ ] Documentation of the TLS-backend split (rustls-aws-lc-rs vs native-
      tls) in `docs/STABILITY.md` § "TLS surface".
- [ ] `--insecure` audit-line emitter — one stderr warn on first use per
      run, prefixed `warning:` (not `[!]`), plain text so CI can grep.
- [ ] `--allow-plaintext-ldap` — already lands per the worktree; verify
      the consent prompt fires on both LdapAuth and OptAuth paths (it
      does, per shared_args.rs code inspection).
- [ ] Explicit `docs/STABILITY.md` § "Retry semantics" asserting
      "no implicit retry on state-changing operations".
- [ ] Synthetic test for the retry non-guarantee: mock a `abuse
      --action add-member` that returns transient wire error; assert
      the verb does NOT retry (would create duplicate memberships).

Every one is spec + a small test — no protocol change, no dep change,
patch-safe.

Everything else in this document is **backlog for 1.5.2+**, not a
1.5.1 blocker.

## 8. Cross-references

- `docs/METHOD_CATALOG_1.5.1.md` §5 D-* — 20 menu-drift rows each need
  to honor the same parameter surface documented here.
- `docs/RESULT_CONTRACT_1.5.1.md` §4 — `status: cancelled` depends on
  the §3 cancellation-token proposal to move from prospective to
  actual.
- `docs/PRE_REVIEW_1.5.1.md` §2 — the `p12 = 0.6` dep pulls PKCS#12
  material; the resulting keys ride the rustls path (`ldap auth`)
  and are NEVER logged. `--insecure` on the LDAPS/schannel side does
  not disable the client-side cert; it only disables server verify.
