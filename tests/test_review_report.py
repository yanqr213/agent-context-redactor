from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_context_redactor.models import ScanResult, SkippedFile
from agent_context_redactor.policy import Policy
from agent_context_redactor.report import render_review
from tests.helpers import scan, write


class ReviewReportTests(unittest.TestCase):
    def test_review_report_marks_ready_when_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "README.md", "hello from a clean context package\n")
            result = scan(root)

            text = render_review(result, Policy.default())

            self.assertIn("**Status:** READY", text)
            self.assertIn("| none | 0 | 0 | none | none |", text)

    def test_review_report_flags_skipped_files(self):
        result = ScanResult(root=".")
        result.skipped.append(SkippedFile("large.log", "larger than max_file_size", 2048))

        text = render_review(result, Policy.default())

        self.assertIn("**Status:** REVIEW", text)
        self.assertIn("large.log", text)
        self.assertIn("larger than max_file_size", text)


if __name__ == "__main__":
    unittest.main()
