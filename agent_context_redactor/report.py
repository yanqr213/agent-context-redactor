from __future__ import annotations

import json
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
                "excerpt": item.excerpt,
            }
            for item in scan.findings
        ],
        "skipped": [item.__dict__ for item in scan.skipped],
    }


def render_json(scan: ScanResult, policy: Policy, mode: str = "scan") -> str:
    return json.dumps(report_data(scan, policy, mode), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


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


def _risk_summary(scan: ScanResult, review_findings: List[Any]) -> str:
    if review_findings:
        return f"{len(review_findings)} finding(s) match required review labels"
    if scan.findings:
        return "findings detected outside required review labels"
    if scan.skipped:
        return "no findings detected, but skipped files need separate handling"
    return "no findings detected"
