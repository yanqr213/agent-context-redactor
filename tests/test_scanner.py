from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_context_redactor.policy import Policy
from tests.helpers import scan, write


class ScannerTests(unittest.TestCase):
    def test_secret_assignment_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "app.py", 'API_KEY = "sampletoken12345"\n')
            result = scan(root)
            self.assertEqual(result.counts_by_kind()["secret_assignment"], 1)

    def test_url_credentials_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "config.txt", "url=postgres://demo:pass12345@db.internal.test/app\n")
            result = scan(root)
            self.assertEqual(result.counts_by_kind()["url_credential"], 1)

    def test_url_credential_takes_priority_over_overlapping_email(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "config.txt", "DATABASE_URL=postgres://demo:pass12345@db.internal.test/app\n")
            result = scan(root)

            self.assertEqual(result.counts_by_kind()["url_credential"], 1)
            self.assertNotIn("email", result.counts_by_kind())
            self.assertNotIn("pass12345", result.findings[0].excerpt)

    def test_email_phone_and_person_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "ticket.txt", "owner = Jane Sample\nemail ops@internal.test\nphone +1 202 555 0199\n")
            result = scan(root)
            self.assertEqual(result.counts_by_kind()["person_name_assignment"], 1)
            self.assertEqual(result.counts_by_kind()["email"], 1)
            self.assertEqual(result.counts_by_kind()["phone"], 1)

    def test_person_name_assignment_does_not_cross_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "ticket.txt", "owner = Jane Sample\nemail ops@internal.test\n")
            result = scan(root)

            self.assertEqual(result.counts_by_kind()["person_name_assignment"], 1)
            self.assertEqual(result.counts_by_kind()["email"], 1)
            self.assertNotIn("email ops", result.findings[0].excerpt)

    def test_large_file_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "big.txt", "x" * 20)
            result = scan(root, Policy.from_mapping({"max_file_size": 10}))
            self.assertEqual(result.skipped[0].reason, "larger than max_file_size")

    def test_binary_file_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "blob.bin"
            path.write_bytes(b"\x00\x01\x02")
            result = scan(root)
            self.assertEqual(result.skipped[0].reason, "binary file")

    def test_excluded_path_not_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "private" / "env.txt", "token" + "=sampletoken12345\n")
            result = scan(root, Policy.from_mapping({"exclude_paths": ["private/**"]}))
            self.assertEqual(len(result.files), 0)


if __name__ == "__main__":
    unittest.main()
