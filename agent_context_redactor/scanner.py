from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Pattern, Tuple

from .models import FileScan, Finding, RedactionPattern, ScanResult, SkippedFile
from .policy import Policy


def scan_paths(paths: Iterable[Path], policy: Policy, root: Optional[Path] = None) -> ScanResult:
    root_path = (root or Path.cwd()).resolve()
    result = ScanResult(root=str(root_path))
    for path in paths:
        target = path.resolve()
        if target.is_dir():
            candidates = _walk_files(target)
        elif target.is_file():
            candidates = iter([target])
        else:
            continue
        for file_path in candidates:
            relative = _relative_posix(file_path, root_path)
            if not policy.is_included(relative):
                continue
            _scan_file(file_path, relative, policy, result)
    return result


def _walk_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def _scan_file(file_path: Path, relative: str, policy: Policy, result: ScanResult) -> None:
    size = file_path.stat().st_size
    if size > policy.max_file_size:
        result.skipped.append(SkippedFile(relative, "larger than max_file_size", size))
        return
    data = file_path.read_bytes()
    if _looks_binary(data):
        result.skipped.append(SkippedFile(relative, "binary file", size))
        return
    text = data.decode("utf-8", errors="replace")
    file_scan = FileScan(path=relative, size=size, sha256=hashlib.sha256(data).hexdigest())
    for pattern in policy.redaction_patterns:
        compiled = _compile_pattern(pattern)
        for match in compiled.finditer(text):
            start, end = _span_for(pattern, match)
            if start == end:
                continue
            value = text[start:end]
            line, column = _line_column(text, start)
            end_line, end_column = _line_column(text, end)
            if line != end_line:
                end_column = column + len(value)
            file_scan.findings.append(
                Finding(
                    path=relative,
                    line=line,
                    column=column,
                    end_column=end_column,
                    start=start,
                    end=end,
                    kind=pattern.name,
                    label=pattern.label,
                    replacement=pattern.replacement,
                    value_hash=hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
                    excerpt="",
                )
            )
    file_scan.findings = _dedupe_overlapping_findings(file_scan.findings)
    file_scan.findings.sort(key=lambda item: (item.start, item.end, item.kind))
    file_scan.findings = _sanitize_excerpts(text, file_scan.findings)
    result.files.append(file_scan)


def _compile_pattern(pattern: RedactionPattern) -> Pattern[str]:
    flags = re.MULTILINE
    for flag in pattern.flags:
        if flag.upper() == "IGNORECASE":
            flags |= re.IGNORECASE
        elif flag.upper() == "DOTALL":
            flags |= re.DOTALL
    return re.compile(pattern.regex, flags)


def _span_for(pattern: RedactionPattern, match: re.Match[str]) -> Tuple[int, int]:
    if pattern.value_group:
        try:
            return match.span(pattern.value_group)
        except IndexError:
            pass
    return match.span(0)


def _line_column(text: str, offset: int) -> Tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_break = text.rfind("\n", 0, offset)
    column = offset + 1 if last_break == -1 else offset - last_break
    return line, column


def _sanitize_excerpts(text: str, findings: List[Finding]) -> List[Finding]:
    sanitized: List[Finding] = []
    for finding in findings:
        line_start, line_end = _line_bounds(text, finding.start)
        line_findings = [
            item
            for item in findings
            if item.start < line_end and item.end > line_start
        ]
        selected = _non_overlapping_for_excerpt(line_findings)
        line = text[line_start:line_end]
        for item in sorted(selected, key=lambda value: value.start, reverse=True):
            start = max(item.start - line_start, 0)
            end = min(item.end - line_start, len(line))
            line = line[:start] + item.replacement + line[end:]
        sanitized.append(replace(finding, excerpt=line.strip()[:240]))
    return sanitized


def _line_bounds(text: str, offset: int) -> Tuple[int, int]:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return start, end


def _non_overlapping_for_excerpt(findings: List[Finding]) -> List[Finding]:
    chosen: List[Finding] = []
    for item in sorted(findings, key=lambda value: (-_label_priority(value.label), value.start, -(value.end - value.start))):
        if any(item.start < other.end and item.end > other.start for other in chosen):
            continue
        chosen.append(item)
    return chosen


def _dedupe_overlapping_findings(findings: List[Finding]) -> List[Finding]:
    selected: List[Finding] = []
    ranked = sorted(
        findings,
        key=lambda item: (-_label_priority(item.label), -(item.end - item.start), item.start, item.kind),
    )
    for item in ranked:
        if any(item.start < other.end and item.end > other.start for other in selected):
            continue
        selected.append(item)
    return selected


def _label_priority(label: str) -> int:
    if label == "credential":
        return 3
    if label == "custom":
        return 2
    if label == "pii":
        return 1
    return 0


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    sample = data[:4096]
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) > 0.30


def _relative_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name
