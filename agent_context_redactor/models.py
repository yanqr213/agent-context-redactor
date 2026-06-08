from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class RedactionPattern:
    name: str
    regex: str
    label: str
    replacement: str
    description: str = ""
    flags: List[str] = field(default_factory=list)
    value_group: Optional[str] = "value"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    end_column: int
    start: int
    end: int
    kind: str
    label: str
    replacement: str
    value_hash: str
    excerpt: str


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str
    size: int


@dataclass
class FileScan:
    path: str
    size: int
    sha256: str
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ScanResult:
    files: List[FileScan] = field(default_factory=list)
    skipped: List[SkippedFile] = field(default_factory=list)
    root: str = "."

    @property
    def findings(self) -> List[Finding]:
        items: List[Finding] = []
        for file_scan in self.files:
            items.extend(file_scan.findings)
        return items

    def counts_by_label(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.label] = counts.get(finding.label, 0) + 1
        return counts

    def counts_by_kind(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.kind] = counts.get(finding.kind, 0) + 1
        return counts
