#!/usr/bin/env python3
"""Sanitize a live-validation output before it becomes a committed receipt.

Input:  a file containing raw adhammer stdout/stderr.
Args:   --dc <ip> --realm <REALM> --admin <DOMAIN\\User> [--pw-env <name>]
Output: stdout, with every lab-identifying value replaced by a placeholder.

Replacements:
    --dc value        -> <dc-ip>
    --realm value     -> <realm>
    admin cred user   -> <admin>
    domain component  -> <domain>
    password value    -> <redacted>
    SID pattern       -> S-1-5-21-XXXX-YYYY-ZZZZ-{RID}   (preserves RID)
    NT hash           -> <nt-hash>
    ccache blob (hex) -> <ccache-blob>
    port 88 / 445 / 636 / 5985 stays as-is (protocol identifiers, not secret)

Pattern-matched (unconditional):
    Known lab-cred substrings from the pre-commit hook list.

Not scrubbed (deliberate):
    Timestamps (needed for chronology)
    Protocol names, opnums, error codes
    Public IP-shape placeholders (10.X.X.X etc.)

Run:
    export ADH_RECEIPT_PASSWORD='...'
    python3 scripts/scrub_receipt.py raw.out --dc 10.0.0.5 --realm CORP.LOCAL \\
        --admin 'CORP\\Administrator' --pw-env ADH_RECEIPT_PASSWORD
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote, quote_plus


ROOT = Path(__file__).resolve().parent.parent
HARD_BLOCK_FILE = ROOT / ".githooks" / "leak-terms.txt"


class UnsafeReceiptError(ValueError):
    """Raw validation output contains a known forbidden identifier."""


def hard_block_patterns() -> tuple[re.Pattern[str], ...]:
    """Load the pre-commit hook's canonical deny patterns."""
    try:
        lines = HARD_BLOCK_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UnsafeReceiptError("canonical hard-block list is unavailable") from exc
    patterns = tuple(
        re.compile(line, flags=re.IGNORECASE)
        for line in lines
        if line.strip()
    )
    if not patterns:
        raise UnsafeReceiptError("canonical hard-block list is empty")
    return patterns


def scrub(
    text: str,
    dc: str,
    realm: str,
    admin: str,
    pw: str | None,
) -> str:
    out = text

    # 1. HARD block — refuse to emit a receipt with any hook-blocked
    #    substring, even if the caller didn't supply the value as a CLI arg.
    for index, pattern in enumerate(hard_block_patterns(), start=1):
        if pattern.search(out):
            raise UnsafeReceiptError(
                f"input matches hard-block pattern #{index}; rotate or remove "
                "the credential before rerunning"
            )

    # 2. Password — never let it survive.
    if pw:
        variants = {
            pw,
            quote(pw, safe=""),
            quote_plus(pw, safe=""),
            json.dumps(pw)[1:-1],
        }
        for value in sorted(variants, key=len, reverse=True):
            if value:
                out = out.replace(value, "<redacted>")

    # 3. DC IP — literal replacement + also common /24 prefix.
    if dc:
        out = out.replace(dc, "<dc-ip>")
        prefix = ".".join(dc.split(".")[:3])
        # Preserve last octet as X to keep report shape readable.
        out = re.sub(
            rf"\b{re.escape(prefix)}\.\d{{1,3}}\b",
            "<dc-subnet>.X",
            out,
        )

    # 4. Realm — both dotted + short-name forms.
    if realm:
        # Redact a DC/host label attached to the realm before replacing the
        # realm itself. Otherwise `dc01.CORP.LOCAL` would retain `dc01`.
        out = re.sub(
            rf"\b(?:[A-Za-z0-9_-]+\.)+{re.escape(realm)}\b",
            "<host>.<realm>",
            out,
            flags=re.IGNORECASE,
        )
        out = re.sub(re.escape(realm), "<realm>", out, flags=re.IGNORECASE)
        short = realm.split(".")[0]
        # short-name domain used in DOMAIN\User idiom
        out = re.sub(
            rf"\b{re.escape(short)}\\",
            "<domain>\\\\",
            out,
            flags=re.IGNORECASE,
        )

    # 5. Admin identity — DOMAIN\User + User@REALM forms.
    if admin:
        user_part = admin.split("\\")[-1].split("@")[0]
        out = out.replace(admin, "<admin>")
        if user_part:
            # Only replace as a standalone token to avoid mangling common
            # English text.
            out = re.sub(
                rf"\b{re.escape(user_part)}\b",
                "<admin>",
                out,
                flags=re.IGNORECASE,
            )

    # 6. Real domain SIDs — preserve the RID (last component) since
    #    that carries meaning (500 = Administrator, 512 = Domain Admins).
    #    Everything before it becomes XXXX-YYYY-ZZZZ.
    out = re.sub(
        r"S-1-5-21-\d+-\d+-\d+-(\d+)",
        r"S-1-5-21-XXXX-YYYY-ZZZZ-\1",
        out,
    )

    # 7. Secret-shaped hex. Catch every standalone value at least as long as
    #    an NT hash, including uncommon 40/48/96-character key/blob shapes.
    def hex_secret(m: re.Match[str]) -> str:
        length = len(m.group(0))
        if length == 32:
            return "<nt-hash>"
        if length == 64:
            return "<aes256-key>"
        return f"<binary-blob-{length}-hex-chars>"

    out = re.sub(
        r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])",
        hex_secret,
        out,
    )

    # 10. Post-check for anything that STILL looks like an IPv4 (a real
    #     IP the caller didn't declare via --dc).
    def ip_check(m: re.Match[str]) -> str:
        ip = m.group(0)
        return "<ip>"

    out = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        ip_check,
        out,
    )

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="raw stdout/stderr file")
    ap.add_argument("--dc", default="", help="DC IP to redact")
    ap.add_argument("--realm", default="", help="AD realm to redact")
    ap.add_argument("--admin", default="", help="admin identity to redact")
    ap.add_argument(
        "--pw-env",
        default="",
        help="name of an environment variable containing the password to redact",
    )
    args = ap.parse_args()

    if args.path == "-":
        text = sys.stdin.read()
    else:
        src = Path(args.path)
        if not src.exists():
            print(f"no such file: {src}", file=sys.stderr)
            return 2
        text = src.read_text(encoding="utf-8", errors="replace")
    if args.pw_env and args.pw_env not in os.environ:
        print(
            f"password environment variable {args.pw_env} is not set",
            file=sys.stderr,
        )
        return 2
    try:
        scrubbed = scrub(
            text,
            args.dc,
            args.realm,
            args.admin,
            os.environ.get(args.pw_env) if args.pw_env else None,
        )
    except UnsafeReceiptError as exc:
        print(f"[scrub_receipt] REFUSING: {exc}", file=sys.stderr)
        return 3
    sys.stdout.write(scrubbed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
