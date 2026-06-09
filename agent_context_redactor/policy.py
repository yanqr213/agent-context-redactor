from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .models import RedactionPattern


DEFAULT_POLICY_NAME = "redactor-policy.json"


DEFAULT_POLICY: Dict[str, Any] = {
    "include_paths": ["**/*"],
    "exclude_paths": [
        ".git/**",
        ".venv/**",
        "venv/**",
        "__pycache__/**",
        ".pytest_cache/**",
        "dist/**",
        "build/**",
        "*.zip",
    ],
    "max_file_size": 1048576,
    "classification_labels": {
        "credential": "Secrets, tokens, keys, passwords, and URL credentials",
        "pii": "Email, phone, and person-like personal data",
        "custom": "Project-defined sensitive pattern",
    },
    "required_review_labels": ["credential"],
    "redaction_patterns": [],
}


BUILTIN_PATTERNS: List[RedactionPattern] = [
    RedactionPattern(
        name="secret_assignment",
        regex=(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|private[_-]?key|"
            r"access[_-]?key|client[_-]?secret|auth[_-]?token)\b"
            r"[ \t]*[:=][ \t]*[\"']?(?P<value>[A-Za-z0-9_./+=:@-]{8,})[\"']?"
        ),
        label="credential",
        replacement="[REDACTED:secret]",
        description="Secret-like key/value assignment",
    ),
    RedactionPattern(
        name="url_credential",
        regex=r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?P<value>[^/\s:@?#]+(?::[^/\s@?#]+)?)(?=@)",
        label="credential",
        replacement="[REDACTED:url-credential]",
        description="Credentials embedded in a URL authority",
    ),
    RedactionPattern(
        name="email",
        regex=r"\b(?P<value>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
        label="pii",
        replacement="[REDACTED:email]",
        description="Email address",
    ),
    RedactionPattern(
        name="phone",
        regex=r"(?<![\w])(?P<value>\+?\d[\d .()/-]{7,}\d)(?![\w])",
        label="pii",
        replacement="[REDACTED:phone]",
        description="Phone-like number",
    ),
    RedactionPattern(
        name="person_name_assignment",
        regex=(
            r"(?i)\b(?:full[_ -]?name|person|contact|owner|assignee)\b"
            r"[ \t]*[:=][ \t]*[\"']?(?P<value>[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3})[\"']?"
        ),
        label="pii",
        replacement="[REDACTED:person]",
        description="Person-like name in an assignment",
    ),
]


@dataclass(frozen=True)
class Policy:
    include_paths: List[str]
    exclude_paths: List[str]
    max_file_size: int
    classification_labels: Mapping[str, str]
    required_review_labels: List[str]
    redaction_patterns: List[RedactionPattern]

    @classmethod
    def default(cls) -> "Policy":
        return cls.from_mapping(DEFAULT_POLICY)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "Policy":
        merged = dict(DEFAULT_POLICY)
        merged.update(data)
        patterns = list(BUILTIN_PATTERNS)
        for item in merged.get("redaction_patterns", []):
            if not isinstance(item, Mapping):
                raise ValueError("redaction_patterns entries must be objects")
            patterns.append(
                RedactionPattern(
                    name=str(item["name"]),
                    regex=str(item["regex"]),
                    label=str(item.get("label", "custom")),
                    replacement=str(item.get("replacement", "[REDACTED:custom]")),
                    description=str(item.get("description", "")),
                    flags=list(item.get("flags", [])),
                    value_group=item.get("value_group", "value"),
                )
            )
        return cls(
            include_paths=list(merged.get("include_paths", ["**/*"])),
            exclude_paths=list(merged.get("exclude_paths", [])),
            max_file_size=int(merged.get("max_file_size", DEFAULT_POLICY["max_file_size"])),
            classification_labels=dict(merged.get("classification_labels", {})),
            required_review_labels=list(merged.get("required_review_labels", [])),
            redaction_patterns=patterns,
        )

    @classmethod
    def load(cls, path: Optional[Path]) -> "Policy":
        if path is None:
            default_path = Path(DEFAULT_POLICY_NAME)
            if default_path.exists():
                path = default_path
            else:
                return cls.default()
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls.from_mapping(data)

    def is_included(self, relative_path: str) -> bool:
        path = _normalize(relative_path)
        included = any(_matches(path, pattern) for pattern in self.include_paths)
        excluded = any(_matches(path, pattern) for pattern in self.exclude_paths)
        return included and not excluded


def write_default_policy(path: Path, force: bool = False) -> None:
    if path.exists() and not force:
        raise FileExistsError(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(DEFAULT_POLICY, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _normalize(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _matches(path: str, pattern: str) -> bool:
    normalized = _normalize(pattern)
    if normalized in ("*", "**", "**/*"):
        return True
    pure = PurePosixPath(path)
    if pure.match(normalized):
        return True
    if normalized.endswith("/**") and (path == normalized[:-3] or path.startswith(normalized[:-2])):
        return True
    if "/" not in normalized and PurePosixPath(path).match(normalized):
        return True
    return False


def load_policy(path: Optional[str]) -> Policy:
    return Policy.load(Path(path) if path else None)


def iter_policy_paths(paths: Iterable[str]) -> List[Path]:
    return [Path(item) for item in paths] if paths else [Path(".")]
