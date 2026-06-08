from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_context_redactor.redactor import make_safe_diff, redact_text
from tests.helpers import scan, write


class RedactionTests(unittest.TestCase):
    def test_redact_text_replaces_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = 'API_KEY = "sampletoken12345"\n'
            write(root / "app.py", original)
            result = scan(root)
            redacted = redact_text(original, result.findings)
            self.assertIn("[REDACTED:secret]", redacted.text)
            self.assertNotIn("sampletoken12345", redacted.text)

    def test_redaction_counts_by_label(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original = "token" + "=sampletoken12345\nemail=ops@internal.test\n"
            write(root / "app.env", original)
            result = scan(root)
            redacted = redact_text(original, result.findings)
            self.assertGreaterEqual(redacted.counts_by_label["credential"], 1)
            self.assertGreaterEqual(redacted.counts_by_label["pii"], 1)

    def test_safe_diff_masks_original(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key_name = "password"
            original = key_name + "=samplepass12345\n"
            write(root / "app.env", original)
            result = scan(root)
            redacted = redact_text(original, result.findings)
            diff = make_safe_diff("app.env", "app.env", redacted)
            self.assertIn("[ORIGINAL:credential:", diff)
            self.assertNotIn("samplepass12345", diff)


if __name__ == "__main__":
    unittest.main()
