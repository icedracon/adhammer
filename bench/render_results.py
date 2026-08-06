#!/usr/bin/env python3
"""Render bench/results.tsv into docs/BENCHMARKS.md — head-to-head timing table
per scenario, with adhammer's speedup vs the fastest competitor.

Reads:  bench/results.tsv  (tab-separated: scenario  tool  ms  exit_code)
Writes: docs/BENCHMARKS.md
"""
import collections
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
TSV = REPO / "bench" / "results.tsv"
OUT = REPO / "docs" / "BENCHMARKS.md"

SCENARIO_DESC = {
    "dcsync-krbtgt": "DCSync `krbtgt` (extract AES256/NT hash via DRSUAPI)",
    "kerberoast": "Kerberoast — SPN enum + TGS-REQ hash harvest",
    "asrep-roast": "AS-REP Roast — no-preauth user harvest",
    "samr-enum": "SAMR user enumeration over `\\samr` named pipe",
    "adcs-enum": "AD CS certification-authority enumeration",
    "ldap-query": "LDAP single-object query (name → SID)",
    "bloodyad-tree": "LDAP tree walk (children under `CN=Users`)",
    "full-audit": "Full LDAP collect + checks + attack-path report",
    "bloodhound-collect": "BloodHound-format DC collection (users/computers/groups/ACLs)",
    "zerologon": "Zerologon (CVE-2020-1472) safe-detect probe",
    "secretsdump-sam": "Local secretsdump — SAM/SYSTEM hive registry read",
    "esc1-enroll": "AD CS ESC1 — request client-auth cert with spoofed UPN SAN",
    "rbcd-write": "RBCD write — msDS-AllowedToActOnBehalfOfOtherIdentity",
    "golden-forge": "Golden ticket forge + KDC accept",
}


def main() -> int:
    if not TSV.exists():
        sys.exit(f"no results file at {TSV} — run bench/run_bench.sh first")
    rows = []
    for line in TSV.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        scenario, tool, ms, rc = parts[0], parts[1], int(parts[2]), int(parts[3])
        rows.append((scenario, tool, ms, rc))

    by_scenario = collections.defaultdict(list)
    for s, t, ms, rc in rows:
        by_scenario[s].append((t, ms, rc))

    md: list[str] = []
    md.append("# ADhammer benchmark scoreboard")
    md.append("")
    md.append(
        "Head-to-head timings vs the standard AD offensive toolkit: "
        "**impacket**, **certipy**, **bloodyAD**, **NetExec (nxc)**. "
        "Wall-clock from process spawn to exit, on a single target Windows Server 2022 DC. "
        "Regenerate with `bench/run_bench.sh` + `python bench/render_results.py`."
    )
    md.append("")
    md.append(
        "> **Testbed:** Windows Server 2022 DC (patched, live). ADhammer runs directly "
        "from a Windows host to the DC. Python-based tools (impacket, certipy, bloodyAD, "
        "NetExec) run from Kali WSL through a SOCKS5 tunnel opened over SSH to the "
        "Windows host (`ssh -D 1080 zevs@host`), then via `proxychains4`. All tools "
        "authenticate as `TESTLAB\\administrator`. Numbers are wall-clock from process "
        "spawn to exit and include tool startup / Python interpreter load — that overhead "
        "is real, operators pay it every invocation, and it's exactly what a single-static "
        "binary avoids."
    )
    md.append("")
    md.append(
        "> **secretsdump-sam note:** ADhammer's secretsdump was recently rewritten around "
        "MS-RRP (WINREG API) — bootkey from `Lsa\\{JD,Skew1,GBG,Data}` key CLASS names, then "
        "SAM users and LSA secrets read directly via `BaseRegOpenKey(REG_OPTION_BACKUP_RESTORE)` "
        "+ `BaseRegEnumKey` + `BaseRegQueryValue`. No hive save, no C$ hive download, byte-"
        "identical NT hashes to impacket. Remaining ~2.6× gap to impacket is per-request "
        "roundtrip overhead (adhammer opens/closes handles serially; impacket pipelines a bit)."
    )
    md.append("")
    md.append("| Scenario | ADhammer | Fastest competitor | Δ (ADhammer / competitor) |")
    md.append("|---|---:|---:|:---:|")
    for scenario in [s for s in SCENARIO_DESC if s in by_scenario]:
        results = by_scenario[scenario]
        adh = next(((t, ms, rc) for t, ms, rc in results if t == "adhammer"), None)
        others = [(t, ms, rc) for t, ms, rc in results if t != "adhammer" and rc == 0]
        others.sort(key=lambda r: r[1])
        adh_str = f"{adh[1]} ms" if adh and adh[2] == 0 else "(failed)"
        if not others:
            others_str, delta = "(all failed)", "—"
        else:
            best = others[0]
            others_str = f"{best[0]} · {best[1]} ms"
            if adh and adh[2] == 0 and best[1] > 0:
                ratio = adh[1] / best[1]
                if ratio < 1:
                    delta = f"✅ **{1/ratio:.1f}× faster**"
                elif ratio < 1.5:
                    delta = f"≈ ({ratio:.1f}×)"
                else:
                    delta = f"⚠️ {ratio:.1f}× slower"
            else:
                delta = "—"
        desc = SCENARIO_DESC[scenario]
        md.append(f"| **{desc}** | {adh_str} | {others_str} | {delta} |")

    md.append("")
    md.append("## All timings per scenario")
    md.append("")
    for scenario in [s for s in SCENARIO_DESC if s in by_scenario]:
        results = sorted(by_scenario[scenario], key=lambda r: (r[2] != 0, r[1]))
        md.append(f"### {SCENARIO_DESC[scenario]}")
        md.append("")
        md.append("| Tool | Wall-clock | Exit |")
        md.append("|---|---:|:---:|")
        for tool, ms, rc in results:
            status = "✅" if rc == 0 else "❌"
            md.append(f"| `{tool}` | {ms} ms | {status} |")
        md.append("")

    md.append("## Why ADhammer where it wins")
    md.append("")
    md.append(
        "- **Single static binary** (musl, ~11 MB) — no Python interpreter, no venv, "
        "no `pip install` on the engagement host."
    )
    md.append(
        "- **All-Rust DCE/RPC stack** — sealed BIND, per-fragment reassembly, "
        "and SEC_TRAILER handling done by hand in `dcerpc` (published on crates.io) "
        "rather than by impacket's decades-old marshaller."
    )
    md.append(
        "- **Attack + report in one process** — `adhammer scan` produces a scored HTML/JSON "
        "report with the executable `adhammer …` command per attack-path hop; the Python "
        "toolkit needs a chain of impacket/certipy/bloodyAD calls to reproduce."
    )
    md.append("")
    md.append("## When to reach for the Python toolkit instead")
    md.append("")
    md.append(
        "- **Fresh attack techniques land in impacket/certipy first.** ADhammer is close but "
        "usually a few weeks behind on ESC/CVE class of things."
    )
    md.append(
        "- **NetExec's plugin ecosystem** for cred sprays across many hosts is broader than "
        "adhammer's `attack spray`."
    )
    md.append(
        "- **BloodyAD's raw LDAP surgery** on unusual attributes is more expressive than "
        "adhammer's `attack abuse` sub-actions."
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
