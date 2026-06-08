from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .manifest import policy_hash_from_mapping
from .packer import pack_zip, redact_to_directory
from .policy import DEFAULT_POLICY, DEFAULT_POLICY_NAME, Policy, iter_policy_paths, load_policy, write_default_policy
from .report import render_json, render_markdown
from .scanner import scan_paths


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileExistsError as exc:
        print(f"error: file exists: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-context-redactor",
        description="Create redacted, reviewable context packages before sharing project context with AI coding agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan files and produce a risk report")
    _add_scan_options(scan)
    scan.set_defaults(func=cmd_scan)

    redact = subparsers.add_parser("redact", help="write redacted files and audit artifacts to a directory")
    _add_scan_options(redact, include_output=False)
    redact.add_argument("--output", "-o", required=True, help="output directory")
    redact.set_defaults(func=cmd_redact)

    pack = subparsers.add_parser("pack", help="write a zip context package with redacted files and audit artifacts")
    _add_scan_options(pack, include_output=False)
    pack.add_argument("--output", "-o", required=True, help="output zip path")
    pack.set_defaults(func=cmd_pack)

    check = subparsers.add_parser("check", help="CI-friendly policy check")
    _add_scan_options(check, check_default="error")
    check.set_defaults(func=cmd_check)

    init_policy = subparsers.add_parser("init-policy", help=f"write {DEFAULT_POLICY_NAME}")
    init_policy.add_argument("--output", "-o", default=DEFAULT_POLICY_NAME, help="policy file path")
    init_policy.add_argument("--force", action="store_true", help="overwrite an existing policy file")
    init_policy.set_defaults(func=cmd_init_policy)
    return parser


def _add_scan_options(parser: argparse.ArgumentParser, include_output: bool = True, check_default: str = "warning") -> None:
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    parser.add_argument("--policy", "-p", help=f"policy JSON path, default: {DEFAULT_POLICY_NAME} if present")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="report format")
    if include_output:
        parser.add_argument("--output", "-o", help="report output path")
    parser.add_argument("--check", choices=["warning", "error"], default=check_default, help="finding severity for command exit behavior")


def cmd_init_policy(args: argparse.Namespace) -> int:
    write_default_policy(Path(args.output), force=args.force)
    print(f"wrote policy: {args.output}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    policy, policy_data = _load_policy_and_data(args.policy)
    paths, root = _paths_and_root(args.paths)
    scan = scan_paths(paths, policy, root=root)
    report = _render(scan, policy, args.format, "scan")
    _write_or_print(report, args.output)
    return _exit_for_findings(scan.findings, args.check)


def cmd_check(args: argparse.Namespace) -> int:
    policy, policy_data = _load_policy_and_data(args.policy)
    paths, root = _paths_and_root(args.paths)
    scan = scan_paths(paths, policy, root=root)
    report = _render(scan, policy, args.format, "check")
    _write_or_print(report, args.output)
    return _exit_for_findings(scan.findings, args.check)


def cmd_redact(args: argparse.Namespace) -> int:
    policy, policy_data = _load_policy_and_data(args.policy)
    paths, root = _paths_and_root(args.paths)
    scan = scan_paths(paths, policy, root=root)
    redact_to_directory(scan, policy, Path(args.output), policy_hash_from_mapping(policy_data))
    print(f"wrote redacted context directory: {args.output}")
    return _exit_for_findings(scan.findings, args.check)


def cmd_pack(args: argparse.Namespace) -> int:
    policy, policy_data = _load_policy_and_data(args.policy)
    paths, root = _paths_and_root(args.paths)
    scan = scan_paths(paths, policy, root=root)
    pack_zip(scan, policy, Path(args.output), policy_hash_from_mapping(policy_data))
    print(f"wrote context package: {args.output}")
    return _exit_for_findings(scan.findings, args.check)


def _load_policy_and_data(path: Optional[str]) -> Tuple[Policy, Dict[str, Any]]:
    if path:
        policy_path = Path(path)
    else:
        policy_path = Path(DEFAULT_POLICY_NAME) if Path(DEFAULT_POLICY_NAME).exists() else None
    if policy_path:
        with policy_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return Policy.from_mapping(data), data
    return load_policy(None), dict(DEFAULT_POLICY)


def _paths_and_root(path_args: List[str]) -> Tuple[List[Path], Path]:
    paths = iter_policy_paths(path_args)
    bases: List[Path] = []
    for path in paths:
        resolved = path.resolve()
        bases.append(resolved if resolved.is_dir() else resolved.parent)
    root = Path(os.path.commonpath([str(base) for base in bases])).resolve()
    return paths, root


def _render(scan: Any, policy: Policy, fmt: str, mode: str) -> str:
    if fmt == "json":
        return render_json(scan, policy, mode)
    return render_markdown(scan, policy, mode)


def _write_or_print(content: str, output: Optional[str]) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    else:
        print(content, end="")


def _exit_for_findings(findings: List[Any], check_mode: str) -> int:
    if findings and check_mode == "error":
        return 1
    return 0
