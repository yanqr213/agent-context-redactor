# Contributing

Thanks for improving `agent-context-redactor`.

## Development

Use Python 3.9 or newer.

```bash
python -m pip install .
python -m unittest discover -s tests
```

Keep runtime dependencies at zero unless a dependency removes substantial risk or complexity. Prefer small, reviewable changes with tests covering policy behavior, scanner findings, redaction output, packing, manifest integrity, CLI behavior, and report formats.

## Security And Privacy

Do not add real credentials, personal data, production hostnames, or private repository links to tests, fixtures, docs, or examples. Use `.test` domains for sample hostnames and email-like strings.

Reports should not expose original sensitive values. When changing output formats, verify that findings contain only positions, labels, hashes, and redacted excerpts.

## Release Checklist

- Run the full test suite.
- Run CLI smoke checks against `examples/sample-project`.
- Check the repository for placeholder leaks and forbidden sample domains.
- Update `CHANGELOG.md`.
