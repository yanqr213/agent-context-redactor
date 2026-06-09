from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .models import ScanResult
from .policy import Policy


def report_data(scan: ScanResult, policy: Policy, mode: str = "scan") -> Dict[str, Any]:
    review_labels = set(policy.required_review_labels)
    review_findings = [item for item in scan.findings if item.label in review_labels]
    return {
        "mode": mode,
        "files_scanned": len(scan.files),
        "files_skipped": len(scan.skipped),
        "findings_total": len(scan.findings),
        "counts_by_label": scan.counts_by_label(),
        "counts_by_kind": scan.counts_by_kind(),
        "required_review_labels": sorted(review_labels),
        "review_required": bool(review_findings),
        "risk_summary": _risk_summary(scan, review_findings),
        "findings": [
            {
                "path": item.path,
                "line": item.line,
                "column": item.column,
                "end_column": item.end_column,
                "kind": item.kind,
                "label": item.label,
                "value_hash": item.value_hash,
                "excerpt": _safe_excerpt(item.excerpt, policy),
            }
            for item in scan.findings
        ],
        "skipped": [item.__dict__ for item in scan.skipped],
    }


def render_json(scan: ScanResult, policy: Policy, mode: str = "scan") -> str:
    return json.dumps(report_data(scan, policy, mode), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def render_sarif(scan: ScanResult, policy: Policy, mode: str = "scan") -> str:
    review_labels = set(policy.required_review_labels)
    rules: Dict[str, Dict[str, Any]] = {}
    for finding in scan.findings:
        rules.setdefault(
            finding.kind,
            {
                "id": finding.kind,
                "name": finding.kind.replace("_", " ").title(),
                "shortDescription": {"text": finding.kind.replace("_", " ")},
                "fullDescription": {"text": f"Detected {finding.label} context that should be reviewed before sharing."},
                "help": {
                    "text": "Review the redacted context package before sharing it with AI coding agents or external tools."
                },
                "defaultConfiguration": {"level": _sarif_level(finding.label, review_labels)},
                "properties": {
                    "label": finding.label,
                    "reviewRequired": finding.label in review_labels,
                    "mode": mode,
                },
            },
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-context-redactor",
                        "informationUri": "https://github.com/yanqr213/agent-context-redactor",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_finding_to_sarif(item, review_labels, policy) for item in scan.findings],
                "properties": {
                    "mode": mode,
                    "root": scan.root,
                    "files_scanned": len(scan.files),
                    "files_skipped": len(scan.skipped),
                    "findings_total": len(scan.findings),
                    "review_required": any(item.label in review_labels for item in scan.findings),
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def render_review(scan: ScanResult, policy: Policy, mode: str = "scan") -> str:
    data = report_data(scan, policy, mode)
    review_labels = set(data["required_review_labels"])
    status, status_detail = _review_status(data)
    lines: List[str] = [
        "# Context Share Review",
        "",
        f"**Status:** {status} - {status_detail}",
        "",
        "## Summary",
        "",
        f"- Mode: {mode}",
        f"- Files scanned: {data['files_scanned']}",
        f"- Files skipped: {data['files_skipped']}",
        f"- Findings: {data['findings_total']}",
        f"- Review required: {'yes' if data['review_required'] else 'no'}",
        f"- Required review labels: {_csv(data['required_review_labels'])}",
        f"- Risk: {data['risk_summary']}",
        "",
        "## Reviewer Checklist",
        "",
        "- [ ] Confirm every required-review finding has an owner decision before sharing context.",
        "- [ ] Open `REVIEW_DIFF.md` when using `redact` or `pack` outputs.",
        "- [ ] Review skipped files separately; they are not represented in the redacted package.",
        "- [ ] Share only the redacted output directory or ZIP, not the original input paths.",
        "",
        "## Hot Files",
        "",
        "| Path | Findings | Review Required | Labels | Kinds |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    hot_files = _hot_file_rows(scan, review_labels)
    for item in hot_files[:10]:
        lines.append(
            f"| {_md(item['path'])} | {item['findings']} | {item['review_required']} | "
            f"{_md(_csv(item['labels']))} | {_md(_csv(item['kinds']))} |"
        )
    if not hot_files:
        lines.append("| none | 0 | 0 | none | none |")

    lines.extend(
        [
            "",
            "## Sample Findings",
            "",
            "| Path | Line | Label | Kind | Hash | Redacted Excerpt |",
            "| --- | ---: | --- | --- | --- | --- |",
        ]
    )
    sample_findings = sorted(
        scan.findings,
        key=lambda item: (0 if item.label in review_labels else 1, item.path, item.line, item.kind),
    )[:10]
    for item in sample_findings:
        lines.append(
            f"| {_md(item.path)} | {item.line} | {_md(item.label)} | {_md(item.kind)} | "
            f"{item.value_hash} | `{_md(_shorten(_safe_excerpt(item.excerpt, policy)))}` |"
        )
    if not sample_findings:
        lines.append("| none | 0 | none | none | none | none |")

    lines.extend(["", "## Skipped Files", "", "| Path | Reason | Size |", "| --- | --- | ---: |"])
    for item in scan.skipped[:10]:
        lines.append(f"| {_md(item.path)} | {_md(item.reason)} | {item.size} |")
    if not scan.skipped:
        lines.append("| none | none | 0 |")
    lines.append("")
    return "\n".join(lines)


def render_markdown(scan: ScanResult, policy: Policy, mode: str = "scan") -> str:
    data = report_data(scan, policy, mode)
    lines: List[str] = [
        f"# Agent Context Redactor {mode.title()} Report",
        "",
        "## Summary",
        "",
        f"- Files scanned: {data['files_scanned']}",
        f"- Files skipped: {data['files_skipped']}",
        f"- Findings: {data['findings_total']}",
        f"- Review required: {'yes' if data['review_required'] else 'no'}",
        f"- Risk: {data['risk_summary']}",
        "",
        "## Counts By Label",
        "",
        "| Label | Count |",
        "| --- | ---: |",
    ]
    for label, count in sorted(data["counts_by_label"].items()):
        lines.append(f"| {label} | {count} |")
    if not data["counts_by_label"]:
        lines.append("| none | 0 |")
    lines.extend(["", "## Findings", "", "| Path | Line | Kind | Label | Hash | Excerpt |", "| --- | ---: | --- | --- | --- | --- |"])
    for item in data["findings"]:
        excerpt = str(item["excerpt"]).replace("|", "\\|")
        lines.append(
            f"| {item['path']} | {item['line']} | {item['kind']} | {item['label']} | "
            f"{item['value_hash']} | `{excerpt}` |"
        )
    if not data["findings"]:
        lines.append("| none | 0 | none | none | none | none |")
    lines.extend(["", "## Skipped Files", "", "| Path | Reason | Size |", "| --- | --- | ---: |"])
    for item in data["skipped"]:
        lines.append(f"| {item['path']} | {item['reason']} | {item['size']} |")
    if not data["skipped"]:
        lines.append("| none | none | 0 |")
    lines.append("")
    return "\n".join(lines)


def _finding_to_sarif(finding: Any, review_labels: set[str], policy: Policy) -> Dict[str, Any]:
    excerpt = _safe_excerpt(finding.excerpt, policy)
    return {
        "ruleId": finding.kind,
        "level": _sarif_level(finding.label, review_labels),
        "message": {"text": f"{finding.label} detected and redacted: {excerpt}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                    "region": {
                        "startLine": max(int(finding.line or 1), 1),
                        "startColumn": max(int(finding.column or 1), 1),
                        "endColumn": max(int(finding.end_column or finding.column or 1), 1),
                    },
                }
            }
        ],
        "partialFingerprints": {"valueHash": finding.value_hash},
        "properties": {
            "kind": finding.kind,
            "label": finding.label,
            "replacement": finding.replacement,
            "value_hash": finding.value_hash,
            "review_required": finding.label in review_labels,
        },
    }


def _sarif_level(label: str, review_labels: set[str]) -> str:
    if label in review_labels or label == "credential":
        return "error"
    if label == "pii":
        return "warning"
    return "note"


def _safe_excerpt(excerpt: str, policy: Policy) -> str:
    redacted = excerpt
    for pattern in policy.redaction_patterns:
        flags = re.MULTILINE
        for flag in pattern.flags:
            if flag.upper() == "IGNORECASE":
                flags |= re.IGNORECASE
            elif flag.upper() == "DOTALL":
                flags |= re.DOTALL
        compiled = re.compile(pattern.regex, flags)
        replacements: List[tuple[int, int, str]] = []
        for match in compiled.finditer(redacted):
            if pattern.value_group:
                try:
                    start, end = match.span(pattern.value_group)
                except IndexError:
                    start, end = match.span(0)
            else:
                start, end = match.span(0)
            if start != end:
                replacements.append((start, end, pattern.replacement))
        for start, end, replacement in reversed(replacements):
            redacted = redacted[:start] + replacement + redacted[end:]
    return redacted


def _review_status(data: Dict[str, Any]) -> tuple[str, str]:
    if data["review_required"]:
        return "BLOCKED", "required-review labels were detected"
    if data["findings_total"]:
        return "REVIEW", "findings were detected outside required-review labels"
    if data["files_skipped"]:
        return "REVIEW", "no findings detected, but skipped files need separate handling"
    return "READY", "no findings or skipped files detected"


def _hot_file_rows(scan: ScanResult, review_labels: set[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for file_scan in scan.files:
        if not file_scan.findings:
            continue
        labels = sorted({item.label for item in file_scan.findings})
        kinds = sorted({item.kind for item in file_scan.findings})
        review_count = sum(1 for item in file_scan.findings if item.label in review_labels)
        rows.append(
            {
                "path": file_scan.path,
                "findings": len(file_scan.findings),
                "review_required": review_count,
                "labels": labels,
                "kinds": kinds,
            }
        )
    rows.sort(key=lambda item: (-int(item["review_required"]), -int(item["findings"]), str(item["path"])))
    return rows


def _csv(values: Any) -> str:
    if not values:
        return "none"
    return ", ".join(str(item) for item in values)


def _md(value: Any) -> str:
    return str(value).replace("\n", " ").replace("|", "\\|")


def _shorten(value: str, limit: int = 160) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _risk_summary(scan: ScanResult, review_findings: List[Any]) -> str:
    if review_findings:
        return f"{len(review_findings)} finding(s) match required review labels"
    if scan.findings:
        return "findings detected outside required review labels"
    if scan.skipped:
        return "no findings detected, but skipped files need separate handling"
    return "no findings detected"
