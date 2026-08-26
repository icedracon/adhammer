# ADhammer Validation Ledger

This file is the local release truth source for the `1.4.5` release line.

No public claim should exceed the status recorded here.

Status meanings:

- `unit-tested` — covered by local unit/integration tests
- `offline-tested` — exercised locally without a live target
- `live-validated` — proven against an authorized lab target
- `validation owed` — code or detection exists, but live proof is still missing

| Capability | Status | Notes |
|---|---|---|
| `scan` core audit / graph / report pipeline | `unit-tested` | Local workspace tests cover the core model and emitters |
| `--json` attack / enum / dump envelope | `offline-tested` | Local parse smoke required before publish |
| Kerberoast / AS-REP roast | `live-validated` | Historical live matrix on Server 2022 / 2025 |
| DCSync | `live-validated` | Single-object path proven; full-domain behaviors depend on operator choice |
| Golden / silver / PtT | `live-validated` | Forging and use paths have live proof in the local release history |
| `attack gmsa` | `live-validated` | Reads `msDS-ManagedPassword` when authorized |
| `attack laps` | `live-validated` | Legacy + Windows LAPS paths; encrypted blobs depend on GKDI rights |
| `attack esc1` | `live-validated` | Supported enrollment path proven on the lab CA |
| `attack icpr-esc1` offline stub / CSR path | `offline-tested` | Stub generation is local and deterministic |
| `attack icpr-esc1` live submit path | `validation owed` | Code path exists; matrix proof still owed |
| `attack relay --target ldap-keycred` | `live-validated` | LDAP relay path has prior proof |
| `attack relay --target adcs-http` (ESC8) | `validation owed` | Handler exists; end-to-end CA proof still owed |
| `attack relay --target icpr` (ESC11) | `validation owed` | Handler exists; CA auth-level policy decides viability |
| `attack mssql` basic exec / impersonation | `offline-tested` | Code path exists; live MSSQL proof still owed |
| `attack dcshadow --drsuapi --prep` | `offline-tested` | Modern path is implemented; public claim should stay conservative |
| `attack dcshadow --drsuapi --push` | `validation owed` | Push path exists; benign-attribute live proof still owed |
| `auto` supported validators | `live-validated` | Only supported findings should be presented as automatable proof |
| `auto` every finding | `validation owed` | Unsupported findings must stay marked potential, not done |
