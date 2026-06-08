from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent_context_redactor.policy import Policy, write_default_policy


class PolicyTests(unittest.TestCase):
    def test_default_policy_includes_builtin_patterns(self):
        policy = Policy.default()
        names = {pattern.name for pattern in policy.redaction_patterns}
        self.assertIn("secret_assignment", names)
        self.assertIn("url_credential", names)

    def test_include_exclude_paths(self):
        policy = Policy.from_mapping({"include_paths": ["src/**"], "exclude_paths": ["src/private/**"]})
        self.assertTrue(policy.is_included("src/app.py"))
        self.assertFalse(policy.is_included("src/private/key.txt"))
        self.assertFalse(policy.is_included("docs/readme.md"))

    def test_custom_regex_loaded(self):
        policy = Policy.from_mapping(
            {
                "redaction_patterns": [
                    {
                        "name": "case_id",
                        "regex": "\\b(?P<value>CASE-[0-9]{4})\\b",
                        "label": "custom",
                        "replacement": "[REDACTED:case]",
                    }
                ]
            }
        )
        self.assertIn("case_id", {pattern.name for pattern in policy.redaction_patterns})

    def test_write_default_policy_creates_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nested" / "policy.json"
            write_default_policy(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("include_paths", data)


if __name__ == "__main__":
    unittest.main()
