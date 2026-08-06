# ADhammer benchmark scoreboard

Head-to-head timings vs the standard AD offensive toolkit: **impacket**, **certipy**, **bloodyAD**, **NetExec (nxc)**. Wall-clock from process spawn to exit, on a single target Windows Server 2022 DC. Regenerate with `bench/run_bench.sh` + `python bench/render_results.py`.

> **Testbed note:** ADhammer runs directly from the Windows host to the DC (NAT-side 172.20.117.1). NetExec/bloodyAD/impacket run from Kali WSL through Windows `netsh interface portproxy` on alternate ports (host SMB owns 445 locally). Impacket-* / certipy — which require Kerberos KDC on 88 and DRSUAPI on dynamic RPC ports — could not be tested in this port-forwarded setup and are documented rather than skipped. Numbers include tool startup + Python interpreter load (that's a real overhead operators pay every invocation, not an unfair advantage for ADhammer).

| Scenario | ADhammer | Fastest competitor | Δ (ADhammer / competitor) |
|---|---:|---:|:---:|
| **DCSync `krbtgt` (extract AES256/NT hash via DRSUAPI)** | 78 ms | (all failed) | — |
| **Kerberoast — SPN enum + TGS-REQ hash harvest** | 85 ms | nxc · 577 ms | ✅ **6.8× faster** |
| **AS-REP Roast — no-preauth user harvest** | 81 ms | nxc · 620 ms | ✅ **7.7× faster** |
| **SAMR user enumeration over `\samr` named pipe** | 241 ms | nxc · 1239 ms | ✅ **5.1× faster** |
| **LDAP single-object query (name → SID)** | 194 ms | (all failed) | — |
| **Full LDAP collect + checks + attack-path report** | 90 ms | nxc · 579 ms | ✅ **6.4× faster** |
| **Zerologon (CVE-2020-1472) safe-detect probe** | 1884 ms | nxc · 1123 ms | ⚠️ 1.7× slower |

## All timings per scenario

### DCSync `krbtgt` (extract AES256/NT hash via DRSUAPI)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 78 ms | ✅ |

### Kerberoast — SPN enum + TGS-REQ hash harvest

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 85 ms | ✅ |
| `nxc` | 577 ms | ✅ |

### AS-REP Roast — no-preauth user harvest

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 81 ms | ✅ |
| `nxc` | 620 ms | ✅ |

### SAMR user enumeration over `\samr` named pipe

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 241 ms | ✅ |
| `nxc` | 1239 ms | ✅ |

### LDAP single-object query (name → SID)

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 194 ms | ✅ |
| `bloodyad` | 626 ms | ❌ |

### Full LDAP collect + checks + attack-path report

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `adhammer` | 90 ms | ✅ |
| `nxc` | 579 ms | ✅ |

### Zerologon (CVE-2020-1472) safe-detect probe

| Tool | Wall-clock | Exit |
|---|---:|:---:|
| `nxc` | 1123 ms | ✅ |
| `adhammer` | 1884 ms | ✅ |

## Why ADhammer where it wins

- **Single static binary** (musl, ~11 MB) — no Python interpreter, no venv, no `pip install` on the engagement host.
- **All-Rust DCE/RPC stack** — sealed BIND, per-fragment reassembly, and SEC_TRAILER handling done by hand in `dcerpc` (published on crates.io) rather than by impacket's decades-old marshaller.
- **Attack + report in one process** — `adhammer scan` produces a scored HTML/JSON report with the executable `adhammer …` command per attack-path hop; the Python toolkit needs a chain of impacket/certipy/bloodyAD calls to reproduce.

## When to reach for the Python toolkit instead

- **Fresh attack techniques land in impacket/certipy first.** ADhammer is close but usually a few weeks behind on ESC/CVE class of things.
- **NetExec's plugin ecosystem** for cred sprays across many hosts is broader than adhammer's `attack spray`.
- **BloodyAD's raw LDAP surgery** on unusual attributes is more expressive than adhammer's `attack abuse` sub-actions.
