from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping

from .models import ScanResult


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_manifest(
    scan: ScanResult,
    redacted_files: Iterable[Mapping[str, Any]],
    policy_hash: str,
) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "tool": "agent-context-redactor",
        "root": scan.root,
        "policy_hash": policy_hash,
        "files_scanned": len(scan.files),
        "files_skipped": len(scan.skipped),
        "findings_total": len(scan.findings),
        "counts_by_label": scan.counts_by_label(),
        "counts_by_kind": scan.counts_by_kind(),
        "redacted_files": list(redacted_files),
        "skipped": [item.__dict__ for item in scan.skipped],
    }
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    manifest["manifest_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return manifest


def policy_hash_from_mapping(policy_data: Mapping[str, Any]) -> str:
    canonical = json.dumps(policy_data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stable_json(data: Mapping[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
