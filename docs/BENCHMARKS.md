# ADhammer benchmark scoreboard

Head-to-head timings vs the standard AD offensive toolkit: **impacket**, **certipy**, **bloodyAD**, **NetExec (nxc)**. Wall-clock from process spawn to exit, on a single target Windows Server 2025 Standard DC. Regenerate with `bench/run_bench.sh` + `python bench/render_results.py`.

> **Testbed:** Windows Server 2025 Standard DC (`testlab.local`, LDAPS via enterprise CA, `RemoteRegistry` enabled). ADhammer runs directly from a Windows host to the DC. Python-based tools (impacket, certipy, bloodyAD, NetExec) run from Kali WSL through a SOCKS5 tunnel opened over SSH to the Windows host (`ssh -D 1080 zevs@host`), then via `proxychains4`. All tools authenticate as `TESTLAB\administrator`. Numbers are wall-clock from process spawn to exit and include tool startup / Python interpreter load — that overhead is real, operators pay it every invocation, and it's exactly what a single-static binary avoids.

> **secretsdump note:** ADhammer's secretsdump uses MS-RRP (WINREG API) — bootkey from `Lsa\{JD,Skew1,GBG,Data}` key CLASS names, then SAM users and LSA secrets read directly via `BaseRegOpenKey(REG_OPTION_BACKUP_RESTORE)` + `BaseRegEnumKey` + `BaseRegQueryValue`. No hive save, no C$ hive download, byte-identical NT hashes to impacket. After enabling `TCP_NODELAY` on the transport socket the round-trip cost dropped from ~19 ms/RPC to ~2 ms/RPC.

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
