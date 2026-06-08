from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_context_redactor.cli import main
from tests.helpers import write


class CliReportTests(unittest.TestCase):
    def test_init_policy_command(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy" / "redactor-policy.json"
            code = main(["init-policy", "--output", str(path)])
            self.assertEqual(code, 0)
            self.assertTrue(path.exists())

    def test_scan_json_output_creates_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            write(root / "app.env", "token" + "=sampletoken12345\n")
            report = Path(temp) / "reports" / "risk.json"
            code = main(["scan", str(root), "--format", "json", "--output", str(report)])
            self.assertEqual(code, 0)
            data = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(data["findings_total"], 1)

    def test_scan_error_check_returns_one(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "app.env", "token" + "=sampletoken12345\n")
            code = main(["scan", str(root), "--check", "error"])
            self.assertEqual(code, 1)

    def test_check_warning_returns_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "app.env", "token" + "=sampletoken12345\n")
            code = main(["check", str(root), "--check", "warning"])
            self.assertEqual(code, 0)

    def test_pack_command_creates_zip_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            write(root / "app.env", "token" + "=sampletoken12345\n")
            out = Path(temp) / "out" / "packs" / "context.zip"
            code = main(["pack", str(root), "--output", str(out)])
            self.assertEqual(code, 0)
            self.assertTrue(out.exists())

    def test_markdown_report_contains_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            write(root / "app.env", "token" + "=sampletoken12345\n")
            report = Path(temp) / "risk.md"
            code = main(["scan", str(root), "--format", "markdown", "--output", str(report)])
            self.assertEqual(code, 0)
            self.assertIn("## Summary", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
