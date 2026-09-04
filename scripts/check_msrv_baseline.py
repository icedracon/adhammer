#!/usr/bin/env python3
"""Fail closed when Cargo.toml `rust-version` drifts from POLICY_MSRV.md.

Enforces the discipline in `docs/POLICY_MSRV.md`: any change to
`[workspace.package].rust-version` must be paired with an update to the
`<!-- MSRV-BASELINE:X.Y -->` marker in the policy doc. That guarantees a
reviewed rationale for every MSRV move rather than a silent bump.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT / "docs" / "POLICY_MSRV.md"
CARGO_PATH = ROOT / "Cargo.toml"

RUST_VERSION_RE = re.compile(r'^\s*rust-version\s*=\s*"(?P<v>[^"]+)"', re.M)
MARKER_RE = re.compile(r"<!--\s*MSRV-BASELINE:(?P<v>[^\s-]+)\s*-->")


def fail(msg: str) -> None:
    print(f"[msrv-baseline] FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    if not CARGO_PATH.is_file():
        fail(f"missing {CARGO_PATH.relative_to(ROOT)}")
    if not POLICY_PATH.is_file():
        fail(f"missing {POLICY_PATH.relative_to(ROOT)}")

    cargo = CARGO_PATH.read_text(encoding="utf-8")
    policy = POLICY_PATH.read_text(encoding="utf-8")

    m = RUST_VERSION_RE.search(cargo)
    if not m:
        fail("Cargo.toml has no `rust-version = \"...\"` line under [workspace.package]")
    manifest_msrv = m.group("v").strip()

    m = MARKER_RE.search(policy)
    if not m:
        fail(
            "docs/POLICY_MSRV.md has no `<!-- MSRV-BASELINE:X.Y -->` marker; "
            "restore it per docs/POLICY_MSRV.md §Baseline"
        )
    policy_msrv = m.group("v").strip()

    if manifest_msrv != policy_msrv:
        fail(
            f"MSRV drift — Cargo.toml declares `{manifest_msrv}` but "
            f"docs/POLICY_MSRV.md baseline says `{policy_msrv}`. Any MSRV move "
            "must edit both in the same reviewed commit; see the policy."
        )

    print(f"[msrv-baseline] green — Cargo.toml + POLICY_MSRV.md agree at {manifest_msrv}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
