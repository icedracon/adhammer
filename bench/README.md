# bench/

Head-to-head benchmark harness — **ADhammer** vs the standard AD offensive toolkit
(**impacket**, **certipy**, **bloodyAD**, **NetExec**).

## Prereqs

- ADhammer built (`cargo build --release`) — the harness expects
  `../target/release/adhammer`.
- **Python side** (needs Kali WSL or a real Kali on the same network as the DC — the
  Windows-side Python install of impacket may fail on Defender-protected boxes):
  ```
  wsl -d kali-linux -e bash -lc \
    'pipx install impacket certipy-ad bloodyAD netexec'
  ```
- **Network**: the DC must be reachable from both the box running ADhammer *and* the WSL
  Kali. Hyper-V "Default Switch" (NAT-only) isolates from WSL — use an External vSwitch
  bound to the physical NIC.

## Run

```bash
HOST=10.0.0.1 DOMAIN=corp.local USER=administrator PW="$ADHAMMER_BENCH_PASSWORD" ./run_bench.sh
python render_results.py
```

## Files

- `run_bench.sh` — runs each scenario across each tool, writes `results.tsv`.
- `render_results.py` — turns `results.tsv` into `../docs/BENCHMARKS.md`.
- `results.tsv` — raw scoreboard (`scenario  tool  wall_ms  exit_code`).
- `full.log` — every command's stdout+stderr, for debugging failed runs.

## Scenarios

| Scenario | What it measures | Compared against |
|---|---|---|
| dcsync-krbtgt | DRSUAPI replication of one account's secrets | impacket-secretsdump, netexec `--ntds vss`/`--dcsync` |
| kerberoast | LDAP SPN enum + TGS-REQ hash harvesting | impacket-GetUserSPNs, netexec `--kerberoasting` |
| samr-enum | SAMR-over-`\samr` user enumeration | impacket-samrdump, netexec `--users` |
| adcs-enum | AD CS CA + template enumeration | certipy find |
| ldap-query | Single LDAP object read (name → SID) | bloodyAD get search |
| full-audit | LDAP collect + checks + attack-path report | netexec ldap options, bloodyAD walks |
| golden-forge | Golden-ticket forge + KDC accept | impacket-ticketer |

Each scenario reports wall-clock; the fastest **successful** competitor becomes ADhammer's
comparison baseline in the rendered scoreboard.
