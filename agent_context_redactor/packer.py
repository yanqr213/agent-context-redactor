from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .manifest import build_manifest, sha256_text, stable_json
from .models import FileScan, ScanResult
from .policy import Policy
from .redactor import make_safe_diff, redact_text
from .report import render_json, render_markdown


def redact_to_directory(scan: ScanResult, policy: Policy, output_dir: Path, policy_hash: str) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    redacted_files, diffs = _write_redacted_files(scan, output_dir)
    manifest = build_manifest(scan, redacted_files, policy_hash)
    (output_dir / "context_manifest.json").write_text(stable_json(manifest), encoding="utf-8", newline="\n")
    (output_dir / "redaction_report.json").write_text(render_json(scan, policy, "redact"), encoding="utf-8", newline="\n")
    (output_dir / "redaction_report.md").write_text(render_markdown(scan, policy, "redact"), encoding="utf-8", newline="\n")
    (output_dir / "REVIEW_DIFF.md").write_text(_join_diffs(diffs), encoding="utf-8", newline="\n")
    return manifest


def pack_zip(scan: ScanResult, policy: Policy, output_zip: Path, policy_hash: str) -> Dict[str, Any]:
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="acr-pack-") as temp_name:
        temp_dir = Path(temp_name)
        manifest = redact_to_directory(scan, policy, temp_dir, policy_hash)
        with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(temp_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(temp_dir).as_posix())
    return manifest


def _write_redacted_files(scan: ScanResult, output_dir: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    root = Path(scan.root)
    redacted_files: List[Dict[str, Any]] = []
    diffs: List[str] = []
    for file_scan in scan.files:
        source = root / file_scan.path
        destination = output_dir / file_scan.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if file_scan.findings:
            original = source.read_text(encoding="utf-8", errors="replace")
            redacted = redact_text(original, file_scan.findings)
            destination.write_text(redacted.text, encoding="utf-8", newline="")
            safe_diff = make_safe_diff(file_scan.path, file_scan.path, redacted)
            if safe_diff.strip():
                diffs.append(f"## {file_scan.path}\n\n```diff\n{safe_diff}\n```\n")
            redactions = len(redacted.applied)
            labels = redacted.counts_by_label
            redacted_sha = sha256_text(redacted.text)
            size = len(redacted.text.encode("utf-8"))
        else:
            shutil.copyfile(source, destination)
            data = destination.read_bytes()
            redactions = 0
            labels = {}
            redacted_sha = __import__("hashlib").sha256(data).hexdigest()
            size = len(data)
        redacted_files.append(
            {
                "path": file_scan.path,
                "original_sha256": file_scan.sha256,
                "redacted_sha256": redacted_sha,
                "size": size,
                "redactions": redactions,
                "redactions_by_label": labels,
            }
        )
    return redacted_files, diffs


def _join_diffs(diffs: Iterable[str]) -> str:
    body = "\n".join(diffs).strip()
    if not body:
        body = "No redaction changes were needed."
    return "# Review Diff\n\nThis diff masks original sensitive values with hash markers before comparison.\n\n" + body + "\n"
