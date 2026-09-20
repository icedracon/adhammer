#!/usr/bin/env python3
"""Regression tests for the live-validation receipt boundary."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import quote

from scripts.scrub_receipt import UnsafeReceiptError, hard_block_patterns, scrub


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
        blocked = "SYNTHETIC-RECEIPT-DENY-123"
        with TemporaryDirectory() as directory:
            deny_file = Path(directory) / "leak-terms.txt"
            deny_file.write_text("synthetic-receipt-deny-[0-9]+\n", encoding="utf-8")
            with patch("scripts.scrub_receipt.HARD_BLOCK_FILE", deny_file):
                with self.assertRaises(UnsafeReceiptError) as caught:
                    scrub(blocked, dc="", realm="", admin="", pw=None)
        self.assertNotIn(blocked, str(caught.exception))

    def test_missing_or_empty_hard_block_file_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            deny_file = Path(directory) / "leak-terms.txt"
            with patch("scripts.scrub_receipt.HARD_BLOCK_FILE", deny_file):
                with self.assertRaisesRegex(UnsafeReceiptError, "unavailable"):
                    hard_block_patterns()
                deny_file.write_text("\n", encoding="utf-8")
                with self.assertRaisesRegex(UnsafeReceiptError, "empty"):
                    hard_block_patterns()

    def test_repository_hard_block_file_loads(self) -> None:
        self.assertTrue(hard_block_patterns())


if __name__ == "__main__":
    unittest.main()
