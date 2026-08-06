# ADhammer benchmark scoreboard

Head-to-head timings vs the standard AD offensive toolkit: **impacket**, **certipy**, **bloodyAD**, **NetExec (nxc)**. Wall-clock from process spawn to exit, on a single target Windows Server 2022 DC. Regenerate with `bench/run_bench.sh` + `python bench/render_results.py`.

> **Testbed:** Windows Server 2022 DC (patched, live). ADhammer runs directly from a Windows host to the DC. Python-based tools (impacket, certipy, bloodyAD, NetExec) run from Kali WSL through a SOCKS5 tunnel opened over SSH to the Windows host (`ssh -D 1080 zevs@host`), then via `proxychains4`. All tools authenticate as `TESTLAB\administrator`. Numbers are wall-clock from process spawn to exit and include tool startup / Python interpreter load — that overhead is real, operators pay it every invocation, and it's exactly what a single-static binary avoids.

> **secretsdump-sam note:** ADhammer's secretsdump was recently rewritten around MS-RRP (WINREG API) — bootkey from `Lsa\{JD,Skew1,GBG,Data}` key CLASS names, then SAM users and LSA secrets read directly via `BaseRegOpenKey(REG_OPTION_BACKUP_RESTORE)` + `BaseRegEnumKey` + `BaseRegQueryValue`. No hive save, no C$ hive download, byte-identical NT hashes to impacket. Remaining ~2.6× gap to impacket is per-request roundtrip overhead (adhammer opens/closes handles serially; impacket pipelines a bit).

| Scenario | ADhammer | Fastest competitor | Δ (ADhammer / competitor) |
|---|---:|---:|:---:|
| **DCSync `krbtgt` (extract AES256/NT hash via DRSUAPI)** | 85 ms | impacket · 335 ms | ✅ **3.9× faster** |
| **Kerberoast — SPN enum + TGS-REQ hash harvest** | 92 ms | impacket · 234 ms | ✅ **2.5× faster** |
| **AS-REP Roast — no-preauth user harvest** | 87 ms | impacket · 220 ms | ✅ **2.5× faster** |
| **SAMR user enumeration over `\samr` named pipe** | 225 ms | impacket · 310 ms | ✅ **1.4× faster** |
| **AD CS certification-authority enumeration** | 147 ms | certipy · 5997 ms | ✅ **40.8× faster** |
| **LDAP single-object query (name → SID)** | 192 ms | bloodyad · 627 ms | ✅ **3.3× faster** |
| **LDAP tree walk (children under `CN=Users`)** | 104 ms | bloodyad · 718 ms | ✅ **6.9× faster** |
| **Full LDAP collect + checks + attack-path report** | 91 ms | nxc · 2058 ms | ✅ **22.6× faster** |
| **BloodHound-format DC collection (users/computers/groups/ACLs)** | 90 ms | bloodhound-python · 30891 ms | ✅ **343.2× faster** |
| **Zerologon (CVE-2020-1472) safe-detect probe** | 1782 ms | nxc · 7779 ms | ✅ **4.4× faster** |
| **Local secretsdump — SAM/SYSTEM hive registry read** | 1083 ms | impacket · 223 ms | ⚠️ 4.9× slower |
| **AD CS ESC1 — request client-auth cert with spoofed UPN SAN** | 315 ms | certipy · 9793 ms | ✅ **31.1× faster** |
| **RBCD write — msDS-AllowedToActOnBehalfOfOtherIdentity** | 80 ms | bloodyad · 363 ms | ✅ **4.5× faster** |

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

### BloodHound-format DC collection (users/computers/groups/ACLs)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 90 ms | ✅ |
| `bloodhound-python` | 30891 ms | ✅ |

### Zerologon (CVE-2020-1472) safe-detect probe

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 1782 ms | ✅ |
| `nxc` | 7779 ms | ✅ |

### Local secretsdump — SAM/SYSTEM hive registry read

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `impacket` | 223 ms | ✅ |
| `adhammer` | 1083 ms | ✅ |

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
