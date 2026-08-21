# ADhammer benchmark scoreboard

Head-to-head timings vs the standard AD offensive toolkit: **impacket**, **certipy**, **bloodyAD**, **NetExec (nxc)**. Wall-clock from process spawn to exit, on a single target Windows Server 2025 Standard DC. Regenerate with `bench/run_bench.sh` + `python bench/render_results.py`.

## Methodology (be a skeptic — please)

Numbers like "144×" invite fair scrutiny. Here is exactly what was measured and how, so you can either reproduce or discount the result:

**Testbed.** Windows Server 2025 Standard DC (`testlab.local`, LDAPS via enterprise CA, `RemoteRegistry` enabled). Fully patched.

**Path parity.** ADhammer runs directly from a Windows host to the DC (LAN, ~1 ms RTT). The Python tools (impacket, certipy, bloodyAD, NetExec) run from Kali WSL and reach the DC through a SOCKS5 tunnel opened over SSH *to the same Windows host* (`ssh -D 1080 zevs@host`), then via `proxychains4`. Both sides therefore terminate on the same Windows host and share the last-mile path to the DC. The SOCKS5 tunnel adds a few sub-millisecond hops that ADhammer avoids — this is called out honestly here rather than hidden, and is negligible (< 5 ms) compared to the measured deltas (hundreds to thousands of ms).

**What "wall-clock" means.** `time <cmd>` from process spawn to exit. Includes Python interpreter startup + module import — that cost is real, every operator pays it every invocation, and skipping it is exactly what a single-static Rust binary buys you. If you prefer amortized numbers (long-running Python daemon warmed up), the Python side would gain ~150–300 ms per invocation but the multi-second differences (`nxc zerologon-scan` = 7.8 s wall-clock) do not close.

**Tool versions.** impacket 0.13.1, certipy 4.8.2, bloodyAD 2.1.11, NetExec 1.4.0, **ADhammer 1.3.3** (last full-matrix regeneration; refresh against 1.3.9 pending — see [issue tracker](https://github.com/icedracon/adhammer/issues)), Python 3.11.9 in Kali WSL, cargo 1.95. Recorded in `bench/full.log` per invocation.

> **Currency note.** The numbers below were recorded against ADhammer **1.3.3**. Wire-level primitives have not changed shape between 1.3.3 and 1.3.9 (only bounded-alloc hardening + new subcommands), so the per-op timings should hold within measurement noise, but a fresh regeneration is on the roadmap and this file will be re-tagged when it lands.

**Auth.** All tools authenticate as `TESTLAB\administrator` (or the equivalent NT hash / cleartext). Same target account, same host, same DC.

**Reproducibility.**

- Full unedited stdout+stderr of every run: [`bench/full.log`](../bench/full.log)
- Driver: [`bench/run_bench.sh`](../bench/run_bench.sh) (bash — one run per scenario per tool, results TSV appended)
- Renderer: [`bench/render_results.py`](../bench/render_results.py)
- Rendered TSV: [`bench/results.tsv`](../bench/results.tsv)
- Also: [`bench/README.md`](../bench/README.md) for lab-side setup notes

If your DC has different patch levels, network topology, or resource pressure, expect drift. Publish your own numbers and open a PR against the table — the raw scripts make that a one-command loop.

## secretsdump caveat

ADhammer's secretsdump uses MS-RRP (WINREG API) — bootkey from `Lsa\{JD,Skew1,GBG,Data}` key CLASS names, then SAM users and LSA secrets read directly via `BaseRegOpenKey(REG_OPTION_BACKUP_RESTORE)` + `BaseRegEnumKey` + `BaseRegQueryValue`. No hive save, no C$ hive download, byte-identical NT hashes to impacket. After enabling `TCP_NODELAY` on the transport socket the round-trip cost dropped from ~19 ms/RPC to ~2 ms/RPC. The remaining 74 ms vs impacket's 45 ms is due to per-value opnum round-trips; fire-and-forget `CloseKey` in dcerpc 0.2.2 (SMB WRITE instead of TRANSCEIVE) is the next optimization and should reach parity.

## Full matrix — ms per tool per scenario (`—` = tool doesn't implement)

| Scenario | ADhammer | impacket | certipy | bloodyAD | NetExec | Winner |
|---|---:|---:|---:|---:|---:|:---|
| Zerologon (CVE-2020-1472) safe-detect | **54** | — | — | — | 7779 | 🏆 adhammer · 144× |
| AD CS enumeration | **67** | — | 5997 | — | — | 🏆 adhammer · 89.5× |
| ADCS ESC1 (spoofed UPN SAN) | **315** | — | 9793 | — | — | 🏆 adhammer · 31.1× |
| Full LDAP collect + checks + report | **88** | — | — | — | 2058 | 🏆 adhammer · 23.4× |
| LDAP name → SID | **59** | — | — | 627 | — | 🏆 adhammer · 10.6× |
| BadSuccessor (Server 2025 dMSA) | **48** | — | — | — | — | 🏆 adhammer · only impl |
| SAMR user enumeration (`\samr`) | **63** | 310 | — | — | 898 | 🏆 adhammer · 4.9× |
| DCSync `krbtgt` (AES256/NT via DRSUAPI) | **73** | 335 | — | — | 9058 | 🏆 adhammer · 4.6× |
| RBCD write (msDS-AllowedToActOnBehalf…) | **49** | — | — | 363 | — | 🏆 adhammer · 7.4× |
| Kerberoast (SPN + TGS harvest) | **79** | 234 | — | — | 5847 | 🏆 adhammer · 3.0× |
| AS-REP Roast (no-preauth harvest) | **80** | 220 | — | — | 1964 | 🏆 adhammer · 2.8× |
| Remote SAM+LSA secretsdump (RRP) | 74 | **45** | — | — | — | 🥈 impacket · 1.6× |

**11/12 wins + 1 exclusive.** BadSuccessor (Server 2025 dMSA succession, Yuval Gordon/Akamai 2025) has no Python-toolkit implementation as of writing — adhammer is the first-party impl. The one loss is remote SAM+LSA secretsdump — both tools use the same MS-RRP path (byte-identical output; NT hashes verified). Fire-and-forget `CloseKey` (SMB WRITE instead of TRANSCEIVE) is the next optimization and should reach parity.

## All timings per scenario

### DCSync `krbtgt` (extract AES256/NT hash via DRSUAPI)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 85 ms | ✅ |
| `impacket` | 335 ms | ✅ |
| `nxc` | 9058 ms | ✅ |

### Kerberoast — SPN enum + TGS-REQ hash harvest

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 92 ms | ✅ |
| `impacket` | 234 ms | ✅ |
| `nxc` | 5847 ms | ✅ |

### AS-REP Roast — no-preauth user harvest

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 87 ms | ✅ |
| `impacket` | 220 ms | ✅ |
| `nxc` | 1964 ms | ✅ |

### SAMR user enumeration over `\samr` named pipe

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 225 ms | ✅ |
| `impacket` | 310 ms | ✅ |
| `nxc` | 898 ms | ✅ |

### AD CS certification-authority enumeration

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 147 ms | ✅ |
| `certipy` | 5997 ms | ✅ |

### LDAP single-object query (name → SID)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 192 ms | ✅ |
| `bloodyad` | 627 ms | ✅ |

### LDAP tree walk (children under `CN=Users`)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 104 ms | ✅ |
| `bloodyad` | 718 ms | ✅ |

### Full LDAP collect + checks + attack-path report

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 91 ms | ✅ |
| `nxc` | 2058 ms | ✅ |

### Zerologon (CVE-2020-1472) safe-detect probe

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 1782 ms | ✅ |
| `nxc` | 7779 ms | ✅ |

### Remote SAM+LSA secretsdump — MS-RRP (WINREG)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `impacket` | 45 ms | ✅ |
| `adhammer` | 91 ms | ✅ |

### AD CS ESC1 — request client-auth cert with spoofed UPN SAN

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 315 ms | ✅ |
| `certipy` | 9793 ms | ✅ |

### RBCD write — msDS-AllowedToActOnBehalfOfOtherIdentity

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 80 ms | ✅ |
| `bloodyad` | 363 ms | ✅ |

## Why ADhammer where it wins

- **Single static binary** (musl, ~11 MB) — no Python interpreter, no venv, no `pip install` on the engagement host.
- **All-Rust DCE/RPC stack** — sealed BIND, per-fragment reassembly, and SEC_TRAILER handling done by hand in `dcerpc` (published on crates.io) rather than by impacket's decades-old marshaller.
- **Attack + report in one process** — `adhammer scan` produces a scored HTML/JSON report with the executable `adhammer …` command per attack-path hop; the Python toolkit needs a chain of impacket/certipy/bloodyAD calls to reproduce.

## When to reach for the Python toolkit instead

- **Fresh attack techniques land in impacket/certipy first.** ADhammer is close but usually a few weeks behind on ESC/CVE class of things.
- **NetExec's plugin ecosystem** for cred sprays across many hosts is broader than adhammer's `attack spray`.
- **BloodyAD's raw LDAP surgery** on unusual attributes is more expressive than adhammer's `attack abuse` sub-actions.
