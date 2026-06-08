from __future__ import annotations

from pathlib import Path
from typing import Optional

from agent_context_redactor.policy import Policy
from agent_context_redactor.scanner import scan_paths


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def scan(root: Path, policy: Optional[Policy] = None):
    return scan_paths([root], policy or Policy.default(), root=root)
