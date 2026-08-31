#!/usr/bin/env python3
"""Regression tests for the live-validation receipt boundary."""

from __future__ import annotations

import unittest
from urllib.parse import quote

from scripts.scrub_receipt import UnsafeReceiptError, scrub


class ScrubReceiptTests(unittest.TestCase):
    def test_redacts_declared_identifiers_and_secret_shapes(self) -> None:
        password = "P@ss word!$"
        nt_hash = "ab" * 16
        odd_blob = "cd" * 48
        text = (
            "Bound to dc01.CoRp.LoCaL at 10.20.30.40; peer 192.168.50.1; "
            "admin CORP\\ADMINISTRATOR; "
            f"password={password}; encoded={quote(password, safe='')}; "
            "SID S-1-5-21-111222333-444555666-777888999-500; "
            f"hash={nt_hash}; blob={odd_blob}"
        )

        got = scrub(
            text,
            dc="10.20.30.40",
            realm="corp.local",
            admin="corp\\Administrator",
            pw=password,
        )

        for sensitive in [
            password,
            quote(password, safe=""),
            "dc01",
            "corp.local",
            "Administrator",
            "10.20.30.40",
            "192.168.50.1",
            nt_hash,
            odd_blob,
        ]:
            self.assertNotIn(sensitive.lower(), got.lower())
        self.assertIn("S-1-5-21-XXXX-YYYY-ZZZZ-500", got)
        self.assertIn("<binary-blob-96-hex-chars>", got)

    def test_hard_block_patterns_refuse_without_echoing_the_value(self) -> None:
        blocked = "Zikurat" + "7"
        with self.assertRaises(UnsafeReceiptError) as caught:
            scrub(blocked, dc="", realm="", admin="", pw=None)
        self.assertNotIn(blocked, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
