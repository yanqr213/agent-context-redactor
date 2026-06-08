from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from .models import Finding


@dataclass(frozen=True)
class RedactedText:
    text: str
    masked_original: str
    counts_by_label: Dict[str, int]
    applied: List[Finding]


def redact_text(text: str, findings: Iterable[Finding]) -> RedactedText:
    usable = _non_overlapping(sorted(findings, key=lambda item: (item.start, item.end)))
    redacted, counts = _replace_spans(text, usable, masked=False)
    masked, _ = _replace_spans(text, usable, masked=True)
    return RedactedText(redacted, masked, counts, usable)


def make_safe_diff(original_path: str, redacted_path: str, redacted: RedactedText) -> str:
    before = redacted.masked_original.splitlines(keepends=True)
    after = redacted.text.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            before,
            after,
            fromfile=f"a/{original_path}",
            tofile=f"b/{redacted_path}",
            lineterm="",
        )
    )


def _replace_spans(text: str, findings: List[Finding], masked: bool) -> Tuple[str, Dict[str, int]]:
    pieces: List[str] = []
    counts: Dict[str, int] = {}
    cursor = 0
    for finding in findings:
        pieces.append(text[cursor:finding.start])
        if masked:
            pieces.append(f"[ORIGINAL:{finding.label}:{finding.value_hash}]")
        else:
            pieces.append(finding.replacement)
            counts[finding.label] = counts.get(finding.label, 0) + 1
        cursor = finding.end
    pieces.append(text[cursor:])
    return "".join(pieces), counts


def _non_overlapping(findings: List[Finding]) -> List[Finding]:
    selected: List[Finding] = []
    occupied_until = -1
    for finding in findings:
        if finding.start < occupied_until:
            continue
        selected.append(finding)
        occupied_until = finding.end
    return selected
