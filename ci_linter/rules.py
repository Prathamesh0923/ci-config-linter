"""Lint rules for GitHub Actions workflows.

Each rule is a function `(workflow, options) -> Iterable[Finding]`, registered
with the @rule decorator. Rule IDs are stable and can be disabled from the CLI
or with an inline `# cilint: ignore=CI001` comment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .models import Finding, Severity, Workflow


@dataclass
class LintOptions:
    trusted_owners: set[str] = field(default_factory=set)
    require_timeout: bool = True


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    description: str
    func: Callable[[Workflow, LintOptions], Iterable[Finding]]


RULES: list[Rule] = []


def rule(rule_id: str, name: str, description: str):
    def decorator(func):
        RULES.append(Rule(rule_id, name, description, func))
        return func

    return decorator


def _finding(rule_id, name, severity, message, wf, line, job=None) -> Finding:
    return Finding(rule_id, name, severity, message, wf.path, line, job)


# --------------------------------------------------------------------------
# CI001 - unpinned actions
# --------------------------------------------------------------------------

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
BRANCH_REFS = {"main", "master", "develop", "dev", "trunk", "head", "latest", "stable", "release"}


def _check_uses_ref(uses: str, options: LintOptions):
    """Return (severity, message) if `uses` is not pinned, else None."""
    uses = uses.strip()
    if uses.startswith("./") or uses.startswith(".\\"):
        return None  # local action, same repo
    if uses.startswith("docker://"):
        if DIGEST_RE.search(uses):
            return None
        return Severity.WARNING, f"Docker image '{uses}' is not pinned to a sha256 digest"
    if "@" not in uses:
        return Severity.ERROR, f"Action '{uses}' has no version ref at all"
    target, ref = uses.rsplit("@", 1)
    owner = target.split("/", 1)[0].lower()
    if owner in options.trusted_owners:
        return None
    if SHA_RE.match(ref):
        return None
    if ref.lower() in BRANCH_REFS:
        return Severity.ERROR, (
            f"Action '{uses}' is pinned to branch '{ref}'; pin to a full commit SHA"
        )
    return Severity.WARNING, (
        f"Action '{uses}' is pinned to mutable tag '{ref}'; pin to a full 40-char commit SHA"
    )


@rule("CI001", "unpinned-action", "Third-party actions should be pinned to a full commit SHA.")
def unpinned_action(wf: Workflow, options: LintOptions):
    for job in wf.jobs:
        if job.uses:
            res = _check_uses_ref(job.uses, options)
            if res:
                yield _finding("CI001", "unpinned-action", res[0], res[1], wf,
                               job.data.line_of("uses"), job.job_id)
        for step in job.steps:
            if step.uses:
                res = _check_uses_ref(step.uses, options)
                if res:
                    yield _finding("CI001", "unpinned-action", res[0], res[1], wf,
                                   step.line_of("uses"), job.job_id)


# --------------------------------------------------------------------------
# CI002 - script injection via untrusted contexts
# --------------------------------------------------------------------------

UNTRUSTED_PATTERNS = [
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.event\.pages\.[^}]*\.page_name",
    r"github\.event\.commits\.[^}]*\.message",
    r"github\.event\.commits\.[^}]*\.author\.(email|name)",
    r"github\.event\.head_commit\.message",
    r"github\.event\.head_commit\.author\.(email|name)",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.pull_request\.head\.repo\.default_branch",
    r"github\.event\.workflow_run\.head_branch",
    r"github\.event\.workflow_run\.head_commit\.message",
    r"github\.head_ref",
]
EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
UNTRUSTED_RE = re.compile("|".join(f"(?:{p})" for p in UNTRUSTED_PATTERNS), re.IGNORECASE)


def _untrusted_exprs(text: str) -> list[str]:
    hits = []
    for match in EXPR_RE.finditer(text):
        expr = match.group(1)
        found = UNTRUSTED_RE.search(expr)
        if found:
            hits.append(found.group(0))
    return hits


@rule("CI002", "script-injection",
      "Untrusted event data must not be interpolated directly into scripts.")
def script_injection(wf: Workflow, options: LintOptions):
    for job, step in wf.all_steps():
        sources = []
        if step.run:
            sources.append(("run", step.run, step.line_of("run")))
        if step.action_name == "actions/github-script":
            script = step.with_.get("script")
            if isinstance(script, str):
                sources.append(("github-script", script, step.line_of("with")))
        for kind, text, line in sources:
            for expr in sorted(set(_untrusted_exprs(text))):
                yield _finding(
                    "CI002", "script-injection", Severity.ERROR,
                    f"Untrusted input '${{{{ {expr} }}}}' is interpolated into a {kind} "
                    "script; pass it through an env variable instead",
                    wf, line, job.job_id,
                )


# --------------------------------------------------------------------------
# CI003 - pull_request_target / workflow_run checking out untrusted code
# --------------------------------------------------------------------------

PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
UNTRUSTED_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|"
    r"github\.event\.workflow_run\.head_(sha|branch)|refs/pull/",
    re.IGNORECASE,
)


@rule("CI003", "untrusted-checkout",
      "Privileged triggers must not check out and run pull request code.")
def untrusted_checkout(wf: Workflow, options: LintOptions):
    triggers = wf.triggers & PRIVILEGED_TRIGGERS
    if not triggers:
        return
    for job, step in wf.all_steps():
        if step.action_name != "actions/checkout":
            continue
        ref = step.with_.get("ref")
        repo = step.with_.get("repository")
        values = " ".join(str(v) for v in (ref, repo) if v is not None)
        if values and (UNTRUSTED_REF_RE.search(values)
                       or "pull_request.head.repo" in values):
            yield _finding(
                "CI003", "untrusted-checkout", Severity.ERROR,
                f"Workflow runs on '{', '.join(sorted(triggers))}' (has secrets and write "
                "token) but checks out untrusted pull request code",
                wf, step.line_of("with"), job.job_id,
            )


# --------------------------------------------------------------------------
# CI004 / CI005 - permissions
# --------------------------------------------------------------------------

@rule("CI004", "missing-permissions",
      "Workflows should declare least-privilege GITHUB_TOKEN permissions.")
def missing_permissions(wf: Workflow, options: LintOptions):
    if "permissions" in wf.data:
        return
    missing = [j.job_id for j in wf.jobs if "permissions" not in j.data]
    if not missing:
        return
    yield _finding(
        "CI004", "missing-permissions", Severity.WARNING,
        "No 'permissions' block at workflow level and job(s) "
        f"{', '.join(missing)} do not set one; GITHUB_TOKEN gets default (possibly write) access",
        wf, wf.on_line or 1,
    )


def _check_perms(value, wf, line, job_id=None):
    if value == "write-all":
        yield _finding("CI005", "excessive-permissions", Severity.ERROR,
                       "permissions: write-all grants write access to every scope",
                       wf, line, job_id)
    elif isinstance(value, dict):
        for scope, level in value.items():
            if scope in ("contents", "actions", "packages", "id-token") and level == "write" \
                    and job_id is None:
                yield _finding(
                    "CI005", "excessive-permissions", Severity.INFO,
                    f"Workflow-level '{scope}: write' applies to every job; "
                    "consider moving it to the job that needs it",
                    wf, value.line_of(scope, line) if hasattr(value, "line_of") else line,
                )


@rule("CI005", "excessive-permissions", "Avoid broad write permissions.")
def excessive_permissions(wf: Workflow, options: LintOptions):
    if "permissions" in wf.data:
        yield from _check_perms(wf.data["permissions"], wf, wf.data.line_of("permissions"))
    for job in wf.jobs:
        if "permissions" in job.data:
            yield from _check_perms(job.data["permissions"], wf,
                                    job.data.line_of("permissions"), job.job_id)


# --------------------------------------------------------------------------
# CI006 - hard-coded secrets
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("GitHub token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
]
SENSITIVE_KEY_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key)",
                              re.IGNORECASE)


def _walk_strings(node, key_path=(), line=0):
    """Yield (key, value, line) for every string scalar in a structure."""
    if isinstance(node, dict):
        for k, v in node.items():
            k_line = node.line_of(k, line) if hasattr(node, "line_of") else line
            if isinstance(v, str):
                yield str(k), v, k_line
            else:
                yield from _walk_strings(v, key_path + (k,), k_line)
    elif isinstance(node, list):
        lines = getattr(node, "item_lines", [])
        for i, item in enumerate(node):
            item_line = lines[i] if i < len(lines) else line
            if isinstance(item, str):
                yield "", item, item_line
            else:
                yield from _walk_strings(item, key_path, item_line)


@rule("CI006", "hardcoded-secret", "Credentials must come from secrets, not literals.")
def hardcoded_secret(wf: Workflow, options: LintOptions):
    seen: set[tuple[int, str]] = set()
    for key, value, line in _walk_strings(wf.data):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(value) and (line, label) not in seen:
                seen.add((line, label))
                yield _finding("CI006", "hardcoded-secret", Severity.ERROR,
                               f"Possible hard-coded {label} found; use ${{{{ secrets.* }}}}",
                               wf, line)
        if (key and SENSITIVE_KEY_RE.search(key) and value.strip()
                and "${{" not in value and (line, "key") not in seen
                and not any(p.search(value) for _, p in SECRET_PATTERNS)
                and len(value.strip()) >= 6 and " " not in value.strip()):
            seen.add((line, "key"))
            yield _finding("CI006", "hardcoded-secret", Severity.WARNING,
                           f"'{key}' is set to a literal value; use ${{{{ secrets.* }}}} instead",
                           wf, line)


# --------------------------------------------------------------------------
# CI007 - missing dependency cache
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _Ecosystem:
    setup_action: str
    install_re: re.Pattern
    label: str
    cache_on_by_default: bool = False


ECOSYSTEMS = [
    _Ecosystem("actions/setup-node",
               re.compile(r"\b(npm (ci|install|i)\b|yarn( install)?\b|pnpm (i|install)\b)"),
               "npm/yarn/pnpm"),
    _Ecosystem("actions/setup-python",
               re.compile(r"\b(pip3? install|poetry install|pipenv install|uv (sync|pip install))\b"),
               "pip/poetry/pipenv"),
    _Ecosystem("actions/setup-java",
               re.compile(r"(\bmvn\b|\bgradle\b|\./gradlew\b|\./mvnw\b|\bsbt\b)"),
               "maven/gradle/sbt"),
    _Ecosystem("actions/setup-go",
               re.compile(r"\bgo (build|test|mod download|install)\b"),
               "go modules", cache_on_by_default=True),
    _Ecosystem("ruby/setup-ruby",
               re.compile(r"\bbundle( install)?\b"),
               "bundler"),
]
CACHE_ACTIONS = {"actions/cache", "actions/cache/restore"}


@rule("CI007", "missing-cache",
      "Jobs that install dependencies should cache them to speed up builds.")
def missing_cache(wf: Workflow, options: LintOptions):
    for job in wf.jobs:
        if any(s.action_name in CACHE_ACTIONS for s in job.steps):
            continue
        run_text = "\n".join(s.run for s in job.steps if s.run)
        for eco in ECOSYSTEMS:
            setup = next((s for s in job.steps if s.action_name == eco.setup_action), None)
            if not eco.install_re.search(run_text):
                continue
            if setup is None:
                continue
            with_ = setup.with_
            if eco.setup_action == "ruby/setup-ruby":
                cached = str(with_.get("bundler-cache", "")).lower() == "true"
            elif eco.cache_on_by_default:
                cached = str(with_.get("cache", "true")).lower() != "false"
            else:
                cached = bool(with_.get("cache"))
            if not cached:
                yield _finding(
                    "CI007", "missing-cache", Severity.WARNING,
                    f"Job installs {eco.label} dependencies but '{eco.setup_action}' has no "
                    "cache enabled and no actions/cache step is used",
                    wf, setup.line_of("uses"), job.job_id,
                )


# --------------------------------------------------------------------------
# CI008 - self-hosted runners on public PR triggers
# --------------------------------------------------------------------------

def _runs_on_labels(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, dict):
        labels = value.get("labels")
        return _runs_on_labels(labels) if labels is not None else []
    return []


@rule("CI008", "self-hosted-runner-pr",
      "Self-hosted runners should not run untrusted pull request code.")
def self_hosted_pr(wf: Workflow, options: LintOptions):
    pr_triggers = wf.triggers & {"pull_request", "pull_request_target"}
    if not pr_triggers:
        return
    for job in wf.jobs:
        labels = [l.lower() for l in _runs_on_labels(job.data.get("runs-on"))]
        if "self-hosted" in labels:
            yield _finding(
                "CI008", "self-hosted-runner-pr", Severity.WARNING,
                "Job runs on a self-hosted runner and is triggered by pull requests; "
                "forked PRs could execute code on your infrastructure",
                wf, job.data.line_of("runs-on"), job.job_id,
            )


# --------------------------------------------------------------------------
# CI009 - dangerous environment settings
# --------------------------------------------------------------------------

@rule("CI009", "unsafe-commands",
      "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables deprecated, injectable commands.")
def unsafe_commands(wf: Workflow, options: LintOptions):
    def check(env, owner_line, job_id=None):
        if isinstance(env, dict):
            for key, value in env.items():
                if str(key).upper() == "ACTIONS_ALLOW_UNSECURE_COMMANDS" and \
                        str(value).lower() == "true":
                    yield _finding("CI009", "unsafe-commands", Severity.ERROR,
                                   "ACTIONS_ALLOW_UNSECURE_COMMANDS enables set-env/add-path, "
                                   "which allow environment injection",
                                   wf, env.line_of(key, owner_line), job_id)

    yield from check(wf.data.get("env"), wf.data.line_of("env"))
    for job in wf.jobs:
        yield from check(job.data.get("env"), job.line, job.job_id)
        for step in job.steps:
            yield from check(step.data.get("env"), step.line, job.job_id)


# --------------------------------------------------------------------------
# CI010 - piping remote scripts into a shell
# --------------------------------------------------------------------------

CURL_PIPE_RE = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b")


@rule("CI010", "curl-pipe-shell", "Downloading and piping scripts into a shell is unverified.")
def curl_pipe_shell(wf: Workflow, options: LintOptions):
    for job, step in wf.all_steps():
        if step.run and CURL_PIPE_RE.search(step.run):
            yield _finding("CI010", "curl-pipe-shell", Severity.WARNING,
                           "Remote script is piped directly into a shell; download, verify "
                           "a checksum, then execute",
                           wf, step.line_of("run"), job.job_id)


# --------------------------------------------------------------------------
# CI011 - missing timeout
# --------------------------------------------------------------------------

@rule("CI011", "missing-timeout",
      "Jobs without timeout-minutes can run (and bill) for up to 6 hours.")
def missing_timeout(wf: Workflow, options: LintOptions):
    if not options.require_timeout:
        return
    for job in wf.jobs:
        if job.uses:  # reusable workflow call: timeout is not allowed here
            continue
        if "timeout-minutes" not in job.data:
            yield _finding("CI011", "missing-timeout", Severity.INFO,
                           "Job has no 'timeout-minutes'; the default is 360 minutes",
                           wf, job.line, job.job_id)


# --------------------------------------------------------------------------
# CI012 - secrets: inherit on reusable workflows
# --------------------------------------------------------------------------

@rule("CI012", "secrets-inherit",
      "Passing all secrets to reusable workflows breaks least privilege.")
def secrets_inherit(wf: Workflow, options: LintOptions):
    for job in wf.jobs:
        if job.uses and job.data.get("secrets") == "inherit":
            yield _finding("CI012", "secrets-inherit", Severity.WARNING,
                           f"'secrets: inherit' passes every repository secret to '{job.uses}'; "
                           "pass only the secrets it needs",
                           wf, job.data.line_of("secrets"), job.job_id)


# --------------------------------------------------------------------------
# CI013 - structural problems
# --------------------------------------------------------------------------

@rule("CI013", "invalid-structure", "Workflow must have 'on' and 'jobs' sections.")
def invalid_structure(wf: Workflow, options: LintOptions):
    if not wf.triggers:
        yield _finding("CI013", "invalid-structure", Severity.ERROR,
                       "Workflow has no 'on' trigger section", wf, 1)
    jobs = wf.data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        yield _finding("CI013", "invalid-structure", Severity.ERROR,
                       "Workflow has no 'jobs' section", wf, 1)
        return
    for job in wf.jobs:
        if job.uses:
            continue
        if "runs-on" not in job.data:
            yield _finding("CI013", "invalid-structure", Severity.ERROR,
                           "Job is missing 'runs-on'", wf, job.line, job.job_id)
        for step in job.steps:
            if step.uses and step.run:
                yield _finding("CI013", "invalid-structure", Severity.ERROR,
                               "Step has both 'uses' and 'run'", wf, step.line, job.job_id)
            elif not step.uses and not step.run:
                yield _finding("CI013", "invalid-structure", Severity.ERROR,
                               "Step has neither 'uses' nor 'run'", wf, step.line, job.job_id)


RULES_BY_ID = {r.rule_id: r for r in RULES}
