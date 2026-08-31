#!/usr/bin/env python3
"""Sanitize a live-validation output before it becomes a committed receipt.

Input:  a file containing raw adhammer stdout/stderr.
Args:   --dc <ip> --realm <REALM> --admin <DOMAIN\\User> [--pw <value>]
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
    python3 scripts/scrub_receipt.py raw.out --dc 10.0.0.5 --realm CORP.LOCAL \\
        --admin 'CORP\\Administrator' --pw 'hunter2'
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# Substrings the pre-commit hook already grep-blocks. Never let one land
# in a receipt either.
HARD_BLOCK_SUBSTRINGS = (
    "Zikurat2003",  # historical lab password from the audit incident
    "S-1-5-21-4202935557-1141836847-2435275103",
    "93a18bf11f58cf2c9dd7b1db2e9fd7f6",
    "a4cee3971e4a7acc05a5b384f380c76b",
    "3d7d82260a3a2c39039f28e9cede2a47",
)


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
    for s in HARD_BLOCK_SUBSTRINGS:
        if s in out:
            print(
                f"[scrub_receipt] REFUSING: input contains hard-blocked "
                f"substring '{s}'. Fix upstream (rotate lab credential; "
                f"scrub input by hand) before rerunning.",
                file=sys.stderr,
            )
            sys.exit(3)

    # 2. Password — never let it survive.
    if pw:
        out = out.replace(pw, "<redacted>")
        # Also common URL-encoding.
        out = out.replace(
            pw.replace("$", "%24").replace("!", "%21"),
            "<redacted>",
        )

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
        out = out.replace(realm, "<realm>")
        out = out.replace(realm.upper(), "<realm>")
        out = out.replace(realm.lower(), "<realm>")
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
            )

    # 6. Real domain SIDs — preserve the RID (last component) since
    #    that carries meaning (500 = Administrator, 512 = Domain Admins).
    #    Everything before it becomes XXXX-YYYY-ZZZZ.
    out = re.sub(
        r"S-1-5-21-\d+-\d+-\d+-(\d+)",
        r"S-1-5-21-XXXX-YYYY-ZZZZ-\1",
        out,
    )

    # 7. NT hash pattern (32 hex chars, standalone).
    out = re.sub(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])", "<nt-hash>", out)

    # 8. AES256 key (64 hex).
    out = re.sub(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", "<aes256-key>", out)

    # 9. Long hex blobs (128+ hex chars — ccache / TGT bytes).
    out = re.sub(
        r"(?<![0-9a-fA-F])[0-9a-fA-F]{128,}(?![0-9a-fA-F])",
        "<binary-blob-{N}-hex-chars>",
        out,
    )

    # 10. Post-check for anything that STILL looks like an IPv4 (a real
    #     IP the caller didn't declare via --dc).
    def ip_check(m: re.Match[str]) -> str:
        ip = m.group(0)
        # Preserve documented placeholder / private-range shapes.
        if ip.startswith(("10.", "192.168.", "172.")) and ip.endswith(
            (".0", ".1", ".254", ".255")
        ):
            return ip  # obvious placeholder / boundary
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
    ap.add_argument("--pw", default="", help="password value to redact")
    args = ap.parse_args()

    src = Path(args.path)
    if not src.exists():
        print(f"no such file: {src}", file=sys.stderr)
        return 2
    text = src.read_text(encoding="utf-8", errors="replace")
    scrubbed = scrub(text, args.dc, args.realm, args.admin, args.pw)
    sys.stdout.write(scrubbed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
