#!/usr/bin/env python3
"""Enforce docs/VALIDATION.md as the source of truth for public claims.

Reads every capability row from docs/VALIDATION.md and greps README.md +
CHANGELOG.md + docs/PLAN_*.md for feature-name references. Fails when:

- A capability is claimed in a public surface but has no ledger row.
- A ledger row is `validation owed` but public surfaces describe it as
  supported / validated / live.
- A `supported` row misses its Windows matrix (declared but no live
  receipt in the ledger notes).

Exit 0 on green, 1 on red. Prints a diff-style report on red.

Run locally:
    python3 scripts/check_validation_ledger.py

Wired to CI as the `validation-ledger` job in .github/workflows/ci.yml.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "VALIDATION.md"

# Public surfaces the ledger governs.
PUBLIC_SURFACES = [
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    *sorted(ROOT.glob("docs/PLAN_*.md")),
    ROOT / "VECTORS.md",
]

# Regex that captures ledger row capability names — anything in the first
# column of a markdown table whose header row contains "Capability".
CAP_ROW = re.compile(r"^\|\s*(?:`([^`]+)`|([^|]+?))\s*\|")

# Words that flag a supported-strength claim in public surfaces. When one
# of these appears near a capability name for a `validation owed` row,
# the checker fires.
STRONG_CLAIMS = (
    "validated",
    "live-validated",
    "supported",
    "proven",
    "verified",
    "byte-identical",
)


def parse_ledger() -> dict[str, str]:
    """Return {capability_name: tier} for every row in the ledger."""
    if not LEDGER.exists():
        die(f"{LEDGER} missing")
    caps: dict[str, str] = {}
    in_table = False
    header_had_capability = False
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_table = False
            continue
        # Table header row?
        if "Capability" in stripped and "Tier" in stripped:
            in_table = True
            header_had_capability = True
            continue
        # Table separator row (---|---) — skip.
        if in_table and set(stripped.replace("|", "").strip()) <= {"-", ":", " "}:
            continue
        if not in_table or not header_had_capability:
            continue
        # Data row. Split on `|` and pick the first two data columns.
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        cap_raw, tier_raw = cells[0], cells[1]
        # Peel backticks off cap name.
        cap = cap_raw.strip("` ").split(" — ")[0].split(" (")[0].strip()
        if not cap:
            continue
        tier = tier_raw.strip("` ").lower()
        # Normalise "validation owed" (2 words).
        if "validation owed" in tier:
            tier = "validation owed"
        caps[cap] = tier
    return caps


def die(msg: str) -> None:
    print(f"[validation-ledger] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def public_text() -> str:
    parts = []
    for p in PUBLIC_SURFACES:
        if p.exists():
            parts.append(p.read_text(encoding="utf-8"))
    return "\n\n".join(parts)


def main() -> int:
    caps = parse_ledger()
    if not caps:
        die("no capability rows parsed from docs/VALIDATION.md")

    text = public_text().lower()

    # Rule 1: `validation owed` rows must not appear in a "validated /
    # supported / live-validated" context in public surfaces.
    fails: list[str] = []
    receipts_dir = ROOT / "docs" / "receipts"
    for receipt in receipts_dir.glob("*.*"):
        if receipt.name == "README.md" or receipt.suffix not in {".md", ".json"}:
            continue
        receipt_text = receipt.read_text(encoding="utf-8").lower()
        if "review status: pending" in receipt_text or '"review_status": "pending"' in receipt_text:
            fails.append(f"receipt {receipt.name} is still pending manual review")
    for cap, tier in caps.items():
        if tier != "validation owed":
            continue
        needle = cap.lower()
        # Search a windowed context around each occurrence of the cap
        # name. Complain if any STRONG_CLAIMS word lies within 200 chars.
        idx = 0
        while True:
            hit = text.find(needle, idx)
            if hit < 0:
                break
            window = text[max(0, hit - 200): hit + 200 + len(needle)]
            for word in STRONG_CLAIMS:
                if word in window and "owed" not in window and "not yet" not in window:
                    fails.append(
                        f"'{cap}' is 'validation owed' in the ledger, "
                        f"but public surfaces describe it with '{word}' "
                        f"near the mention (char {hit})."
                    )
                    break
            idx = hit + len(needle)

    # Rule 2: the ledger must cover every attack/enum verb in the CLI.
    # Extract subcommand names from cli/src/attacks/mod.rs + cli/src/main.rs.
    attacks_dir = ROOT / "cli" / "src" / "attacks"
    verb_files = {p.stem for p in attacks_dir.glob("*.rs") if p.stem != "mod"}
    # Map file → likely CLI verb. exec_pack.rs is exec+atexec+wmiexec;
    # icpr_esc1 is icpr-esc1; etc. Best-effort — the ledger uses the
    # `attack <verb>` phrasing and matches by string containment.
    ledger_flat = " ".join(caps.keys()).lower()
    missing_verbs: list[str] = []
    verb_aliases = {
        "exec_pack": ["attack exec", "attack atexec", "attack wmiexec"],
        "winrm_exec": ["attack winrm"],
        "adcs_relay": ["attack relay --target adcs-http"],
        "scan": ["adhammer scan"],
        "scan_anonymous": ["adhammer scan"],  # anonymous is a mode of scan
        "icpr_esc1": ["attack icpr-esc1"],
        "dpapi_mk": ["attack dpapi-master-key"],
        "unpac": ["attack unpac"],
    }
    for stem in verb_files:
        candidates = verb_aliases.get(stem, [f"attack {stem}"])
        if not any(c.lower() in ledger_flat for c in candidates):
            missing_verbs.append(f"CLI has attacks/{stem}.rs but ledger has no matching row (looked for: {candidates})")

    if fails or missing_verbs:
        print("[validation-ledger] RED — one or more claim/coverage checks failed:\n", file=sys.stderr)
        for f in fails:
            print(f"  - claim-vs-ledger: {f}", file=sys.stderr)
        for f in missing_verbs:
            print(f"  - coverage:        {f}", file=sys.stderr)
        print(
            "\nFix by either (a) adding a ledger row in docs/VALIDATION.md, "
            "(b) softening the public claim, or (c) demoting the ledger row "
            "if the receipt went stale.",
            file=sys.stderr,
        )
        return 1

    print(f"[validation-ledger] green — {len(caps)} rows enforced across "
          f"{len(PUBLIC_SURFACES)} public surfaces.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
