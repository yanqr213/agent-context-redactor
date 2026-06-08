from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent_context_redactor.manifest import build_manifest, policy_hash_from_mapping
from agent_context_redactor.packer import pack_zip, redact_to_directory
from agent_context_redactor.policy import DEFAULT_POLICY, Policy
from tests.helpers import scan, write


class PackingManifestTests(unittest.TestCase):
    def test_manifest_contains_hash_and_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write(root / "app.env", "token" + "=sampletoken12345\n")
            result = scan(root)
            manifest = build_manifest(result, [], policy_hash_from_mapping(DEFAULT_POLICY))
            self.assertIn("manifest_hash", manifest)
            self.assertEqual(manifest["findings_total"], 1)

    def test_redact_to_directory_preserves_structure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "src"
            out = Path(temp) / "out" / "context"
            write(root / "nested" / "app.env", "token" + "=sampletoken12345\n")
            result = scan(root)
            redact_to_directory(result, Policy.default(), out, policy_hash_from_mapping(DEFAULT_POLICY))
            redacted = (out / "nested" / "app.env").read_text(encoding="utf-8")
            self.assertIn("[REDACTED:secret]", redacted)
            self.assertTrue((out / "context_manifest.json").exists())

    def test_pack_zip_contains_reports_and_redacted_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "src"
            out = Path(temp) / "nested" / "context.zip"
            write(root / "app.env", "token" + "=sampletoken12345\n")
            result = scan(root)
            pack_zip(result, Policy.default(), out, policy_hash_from_mapping(DEFAULT_POLICY))
            with zipfile.ZipFile(out) as archive:
                names = set(archive.namelist())
                self.assertIn("app.env", names)
                self.assertIn("context_manifest.json", names)
                self.assertIn("redaction_report.md", names)

    def test_manifest_file_records_redaction_count(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "src"
            out = Path(temp) / "out"
            write(root / "app.env", "token" + "=sampletoken12345\n")
            result = scan(root)
            redact_to_directory(result, Policy.default(), out, policy_hash_from_mapping(DEFAULT_POLICY))
            manifest = json.loads((out / "context_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["redacted_files"][0]["redactions"], 1)


if __name__ == "__main__":
    unittest.main()
