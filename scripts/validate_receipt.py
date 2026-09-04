#!/usr/bin/env python3
"""Validate every docs/receipts/*.json against docs/receipts/schema.json.

Hand-rolled schema-subset validator so we do not pull `jsonschema` into
the CI Python env just for a handful of receipts. Enforces the fields
scripts/check_validation_ledger.py already relies on, plus the file-
naming convention documented in docs/receipts/README.md.

Ship-gate discipline: this script is the "receipts have a machine-
verified shape" answer to WS-RECEIPT-SCHEMA (see docs/PLAN_1.5.0.md).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECEIPTS_DIR = ROOT / "docs" / "receipts"
SCHEMA_PATH = RECEIPTS_DIR / "schema.json"

VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVIEW_RE = re.compile(r"^(pending|approved.*|rejected.*)$", re.DOTALL)
STATUS_RE = re.compile(r"^(pass|fail|refused|skipped)( \(.*\))?$")
FILENAME_RE = re.compile(r"^(?P<version>[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?)__(?P<label>[A-Za-z0-9_.-]+)\.json$")


def fail(path: Path, msg: str, fails: list) -> None:
    fails.append(f"{path.relative_to(ROOT)}: {msg}")


def check_receipt(path: Path, allowed_labels: set, fails: list) -> None:
    m = FILENAME_RE.match(path.name)
    if not m:
        fail(path, "filename does not match '<version>__<label>.json' convention", fails)
        return

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(path, f"invalid JSON: {e}", fails)
        return
    if not isinstance(data, dict):
        fail(path, "top level must be an object", fails)
        return

    for req in ("version", "binary_sha256", "review_status"):
        if req not in data:
            fail(path, f"missing required field '{req}'", fails)

    v = data.get("version", "")
    if not isinstance(v, str) or not VERSION_RE.match(v):
        fail(path, f"version {v!r} not semver-shaped", fails)
    elif v != m.group("version"):
        fail(path, f"version field '{v}' disagrees with filename '{m.group('version')}'", fails)

    label = data.get("windows_label")
    if label is not None:
        if label not in allowed_labels:
            fail(path, f"windows_label {label!r} not in schema enum {sorted(allowed_labels)}", fails)
        elif label != m.group("label"):
            fail(path, f"windows_label '{label}' disagrees with filename label '{m.group('label')}'", fails)

    sha = data.get("binary_sha256", "")
    if not isinstance(sha, str) or not SHA256_RE.match(sha):
        fail(path, f"binary_sha256 not 64 lowercase hex chars: {sha!r}", fails)

    rs = data.get("review_status", "")
    if not isinstance(rs, str) or not REVIEW_RE.match(rs):
        fail(path, f"review_status not in {{pending, approved..., rejected...}}: {rs!r}", fails)

    verbs = data.get("verbs")
    if verbs is not None:
        if not isinstance(verbs, list):
            fail(path, "'verbs' must be an array when present", fails)
        else:
            for i, entry in enumerate(verbs):
                if not isinstance(entry, dict):
                    fail(path, f"verbs[{i}] must be an object", fails)
                    continue
                for req in ("verb", "status"):
                    if req not in entry:
                        fail(path, f"verbs[{i}] missing required field '{req}'", fails)
                status = entry.get("status", "")
                if isinstance(status, str) and not STATUS_RE.match(status):
                    fail(path, f"verbs[{i}] status {status!r} not in {{pass,fail(...),refused(...),skipped(...)}}", fails)


def main() -> int:
    if not SCHEMA_PATH.is_file():
        print(f"[validate-receipt] FAIL: missing {SCHEMA_PATH.relative_to(ROOT)}", file=sys.stderr)
        return 1
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    allowed_labels = set(schema["properties"]["windows_label"]["enum"])

    fails: list = []
    receipts = sorted(RECEIPTS_DIR.glob("*.json"))
    receipts = [p for p in receipts if p.name != "schema.json"]

    if not receipts:
        print("[validate-receipt] no receipt JSON files found — nothing to validate")
        return 0

    for r in receipts:
        check_receipt(r, allowed_labels, fails)

    if fails:
        print(f"[validate-receipt] RED — {len(fails)} error(s):", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"[validate-receipt] green — {len(receipts)} receipt(s) validated against schema.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
