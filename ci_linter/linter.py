"""Run rules against workflow files and apply suppressions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import yaml

from .loader import LineDict, load_yaml
from .models import Finding, Severity, build_workflow
from .rules import RULES, LintOptions

IGNORE_RE = re.compile(r"#\s*cilint:\s*ignore(?:=([A-Za-z0-9_,\s]+))?", re.IGNORECASE)
IGNORE_FILE_RE = re.compile(r"#\s*cilint:\s*ignore-file\b", re.IGNORECASE)


def _suppressed(finding: Finding, lines: list[str]) -> bool:
    """A finding is suppressed by `# cilint: ignore[=IDS]` on its line or the line above."""
    for idx in (finding.line - 1, finding.line - 2):
        if 0 <= idx < len(lines):
            match = IGNORE_RE.search(lines[idx])
            if not match:
                continue
            # A comment on the previous line only counts if that line is a pure comment.
            if idx == finding.line - 2 and not lines[idx].lstrip().startswith("#"):
                continue
            ids = match.group(1)
            if ids is None:
                return True
            wanted = {i.strip().upper() for i in ids.split(",") if i.strip()}
            if finding.rule_id in wanted:
                return True
    return False


def lint_text(text: str, path: str = "<string>", options: LintOptions | None = None,
              disabled: Iterable[str] = ()) -> list[Finding]:
    options = options or LintOptions()
    disabled = {d.upper() for d in disabled}
    if IGNORE_FILE_RE.search(text):
        return []
    try:
        data = load_yaml(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        return [Finding("CI000", "parse-error", Severity.ERROR,
                        f"Invalid YAML: {problem}", path, line)]
    if not isinstance(data, LineDict):
        return [Finding("CI000", "parse-error", Severity.ERROR,
                        "Workflow file must be a YAML mapping", path, 1)]

    wf = build_workflow(path, text, data)
    lines = wf.lines
    findings: list[Finding] = []
    for r in RULES:
        if r.rule_id in disabled:
            continue
        for f in r.func(wf, options):
            if not _suppressed(f, lines):
                findings.append(f)
    findings.sort(key=lambda f: (f.line, -int(f.severity), f.rule_id))
    return findings


def lint_file(path: str | Path, options: LintOptions | None = None,
              disabled: Iterable[str] = ()) -> list[Finding]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [Finding("CI000", "parse-error", Severity.ERROR,
                        f"Cannot read file: {exc}", str(path), 0)]
    return lint_text(text, str(path), options, disabled)


def discover_files(paths: Iterable[str | Path]) -> list[Path]:
    """Expand directories into *.yml / *.yaml files (sorted, de-duplicated)."""
    found: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            wf_dir = p / ".github" / "workflows"
            base = wf_dir if wf_dir.is_dir() else p
            for ext in ("*.yml", "*.yaml"):
                found.extend(base.rglob(ext))
        elif p.is_file():
            found.append(p)
        else:
            raise FileNotFoundError(f"No such file or directory: {p}")
    seen, unique = set(), []
    for f in sorted(found):
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
