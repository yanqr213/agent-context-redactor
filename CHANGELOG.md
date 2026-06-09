# Changelog

## 0.3.0

- Added `--format review` for concise context-sharing review packets that fit PR comments, CI summaries, and agent handoffs.
- Added review report tests for blocked, ready, and skipped-file states.
- Hardened report excerpts so same-line findings are jointly redacted and overlapping detections prefer higher-risk labels.
- Fixed person-like PII matching so it does not cross line boundaries and hide email findings.
- Added CI smoke coverage for the review report format.
- Updated Chinese and English documentation with the review workflow.

## 0.2.0

- Added SARIF 2.1.0 output for GitHub Code Scanning.
- Added SARIF CLI smoke coverage and report tests.
- Added public GitHub project URLs.

## 0.1.0

- Initial local release.
- Added policy-driven scanning, redaction, reporting, manifest generation, and ZIP packing.
- Added CLI commands: `scan`, `pack`, `redact`, `check`, and `init-policy`.
- Added examples, tests, and CI configuration.
