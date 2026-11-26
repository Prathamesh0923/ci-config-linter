"""Command line interface."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .linter import discover_files, lint_file
from .models import Severity
from .reporters import FORMATTERS, format_text
from .rules import RULES, LintOptions


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ci-lint",
        description="Lint GitHub Actions workflows for security issues, unpinned actions "
                    "and missing caches.",
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="Workflow files or directories (default: . -> .github/workflows)")
    p.add_argument("-f", "--format", choices=sorted(FORMATTERS), default="text",
                   help="Output format (default: text)")
    p.add_argument("--min-severity", default="info", choices=["info", "warning", "error"],
                   help="Hide findings below this severity (default: info)")
    p.add_argument("--fail-on", default="warning", choices=["info", "warning", "error", "never"],
                   help="Exit 1 if any finding is at or above this severity (default: warning)")
    p.add_argument("--disable", action="append", default=[], metavar="RULE_ID",
                   help="Disable a rule (repeatable or comma-separated), e.g. --disable CI011")
    p.add_argument("--trusted-owner", action="append", default=[], metavar="OWNER",
                   help="Skip SHA-pinning checks for actions from this owner (e.g. actions)")
    p.add_argument("--no-timeout-check", action="store_true",
                   help="Do not report jobs without timeout-minutes (CI011)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    p.add_argument("--list-rules", action="store_true", help="List all rules and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _split(values: list[str]) -> list[str]:
    return [v.strip() for item in values for v in item.split(",") if v.strip()]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_rules:
        for r in RULES:
            print(f"{r.rule_id}  {r.name:<24} {r.description}")
        return 0

    options = LintOptions(
        trusted_owners={o.lower() for o in _split(args.trusted_owner)},
        require_timeout=not args.no_timeout_check,
    )
    disabled = _split(args.disable)

    try:
        files = discover_files(args.paths)
    except FileNotFoundError as exc:
        print(f"ci-lint: {exc}", file=sys.stderr)
        return 2
    if not files:
        print("ci-lint: no workflow files found", file=sys.stderr)
        return 2

    min_sev = Severity.parse(args.min_severity)
    findings = []
    for path in files:
        findings.extend(f for f in lint_file(path, options, disabled) if f.severity >= min_sev)

    if args.format == "text":
        color = not args.no_color and sys.stdout.isatty()
        output = format_text(findings, len(files), color=color)
    else:
        output = FORMATTERS[args.format](findings, len(files))
    if output:
        print(output)

    if args.fail_on == "never":
        return 0
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= threshold for f in findings) else 0
