"""Output formatters: text, json and GitHub Actions annotations."""

from __future__ import annotations

import json
from collections import Counter

from .models import Finding, Severity

_COLORS = {Severity.ERROR: "\033[31m", Severity.WARNING: "\033[33m", Severity.INFO: "\033[36m"}
_RESET = "\033[0m"


def format_text(findings: list[Finding], files_checked: int, color: bool = False) -> str:
    out = []
    current = None
    for f in findings:
        if f.path != current:
            if current is not None:
                out.append("")
            out.append(f.path)
            current = f.path
        sev = str(f.severity).upper()
        if color:
            sev = f"{_COLORS[f.severity]}{sev}{_RESET}"
        job = f" [job: {f.job}]" if f.job else ""
        out.append(f"  {f.line:>4}  {sev:<7}  {f.rule_id} {f.rule_name}: {f.message}{job}")
    counts = Counter(f.severity for f in findings)
    if out:
        out.append("")
    out.append(
        f"{files_checked} file(s) checked: {counts[Severity.ERROR]} error(s), "
        f"{counts[Severity.WARNING]} warning(s), {counts[Severity.INFO]} info"
    )
    return "\n".join(out)


def format_json(findings: list[Finding], files_checked: int) -> str:
    counts = Counter(str(f.severity) for f in findings)
    return json.dumps({
        "files_checked": files_checked,
        "summary": {s: counts.get(s, 0) for s in ("error", "warning", "info")},
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def format_github(findings: list[Finding], files_checked: int) -> str:
    """Workflow commands that render as inline annotations on PRs."""
    level = {Severity.ERROR: "error", Severity.WARNING: "warning", Severity.INFO: "notice"}
    lines = []
    for f in findings:
        props = f"file={_escape(f.path)},line={max(f.line, 1)},title={f.rule_id} {f.rule_name}"
        lines.append(f"::{level[f.severity]} {props}::{_escape(f.message)}")
    return "\n".join(lines)


FORMATTERS = {"text": format_text, "json": format_json, "github": format_github}
