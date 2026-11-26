"""Core data types: severities, findings and the parsed workflow."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .loader import LineDict, LineList


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    path: str
    line: int = 0
    job: str | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule": self.rule_name,
            "severity": str(self.severity),
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "job": self.job,
        }


@dataclass
class Step:
    job_id: str
    index: int
    data: LineDict
    line: int

    @property
    def uses(self) -> str | None:
        value = self.data.get("uses")
        return value if isinstance(value, str) else None

    @property
    def run(self) -> str | None:
        value = self.data.get("run")
        return value if isinstance(value, str) else None

    @property
    def with_(self) -> dict:
        value = self.data.get("with")
        return value if isinstance(value, dict) else {}

    @property
    def action_name(self) -> str | None:
        """'actions/checkout@v4' -> 'actions/checkout' (lower-case)."""
        if not self.uses:
            return None
        return self.uses.split("@", 1)[0].strip().lower()

    def line_of(self, key: str) -> int:
        return self.data.line_of(key, self.line)


@dataclass
class Job:
    job_id: str
    data: LineDict
    line: int
    steps: list[Step] = field(default_factory=list)

    @property
    def uses(self) -> str | None:
        """Reusable workflow call (job-level `uses:`)."""
        value = self.data.get("uses")
        return value if isinstance(value, str) else None


@dataclass
class Workflow:
    path: str
    text: str
    data: LineDict
    jobs: list[Job] = field(default_factory=list)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def triggers(self) -> set[str]:
        # YAML 1.1 parses a bare `on:` key as boolean True.
        raw = self.data.get("on", self.data.get(True))
        if isinstance(raw, str):
            return {raw}
        if isinstance(raw, list):
            return {str(t) for t in raw}
        if isinstance(raw, dict):
            return {str(t) for t in raw}
        return set()

    @property
    def on_line(self) -> int:
        if "on" in self.data:
            return self.data.line_of("on")
        return self.data.line_of(True, 1)

    def all_steps(self):
        for job in self.jobs:
            yield from ((job, step) for step in job.steps)


def build_workflow(path: str, text: str, data: LineDict) -> Workflow:
    wf = Workflow(path=path, text=text, data=data)
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job_data in jobs.items():
            if not isinstance(job_data, LineDict):
                continue
            job = Job(job_id=str(job_id), data=job_data, line=jobs.line_of(job_id))
            steps = job_data.get("steps")
            if isinstance(steps, LineList):
                for idx, step_data in enumerate(steps):
                    if isinstance(step_data, LineDict):
                        job.steps.append(Step(job.job_id, idx, step_data, step_data.line))
            wf.jobs.append(job)
    return wf
