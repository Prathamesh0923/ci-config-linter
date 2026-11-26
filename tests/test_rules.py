import textwrap
import unittest

from ci_linter.linter import lint_text
from ci_linter.models import Severity
from ci_linter.rules import LintOptions

SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def lint(yaml_text, **opts):
    options = LintOptions(require_timeout=opts.pop("require_timeout", False), **opts)
    return lint_text(textwrap.dedent(yaml_text), "wf.yml", options)


def ids(findings):
    return [f.rule_id for f in findings]


CLEAN = f"""
name: CI
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@{SHA}
      - run: make test
"""


class CleanWorkflowTest(unittest.TestCase):
    def test_clean_workflow_has_no_findings(self):
        self.assertEqual(lint(CLEAN, require_timeout=True), [])


class UnpinnedActionTest(unittest.TestCase):
    def _wf(self, uses):
        return f"""
        on: push
        permissions: {{}}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: {uses}
        """

    def test_tag_is_warning(self):
        f = [x for x in lint(self._wf("actions/checkout@v4")) if x.rule_id == "CI001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, Severity.WARNING)
        self.assertEqual(f[0].line, 8)

    def test_branch_is_error(self):
        f = [x for x in lint(self._wf("foo/bar@main")) if x.rule_id == "CI001"]
        self.assertEqual(f[0].severity, Severity.ERROR)

    def test_missing_ref_is_error(self):
        f = [x for x in lint(self._wf("foo/bar")) if x.rule_id == "CI001"]
        self.assertEqual(f[0].severity, Severity.ERROR)

    def test_sha_and_local_are_ok(self):
        self.assertNotIn("CI001", ids(lint(self._wf(f"foo/bar@{SHA}"))))
        self.assertNotIn("CI001", ids(lint(self._wf("./.github/actions/x"))))

    def test_docker_without_digest(self):
        self.assertIn("CI001", ids(lint(self._wf("docker://alpine:3.20"))))
        digest = "docker://alpine@sha256:" + "a" * 64
        self.assertNotIn("CI001", ids(lint(self._wf(digest))))

    def test_trusted_owner_skipped(self):
        found = lint(self._wf("actions/checkout@v4"), trusted_owners={"actions"})
        self.assertNotIn("CI001", ids(found))

    def test_reusable_workflow_job(self):
        wf = """
        on: push
        permissions: {}
        jobs:
          call:
            uses: org/repo/.github/workflows/x.yml@main
        """
        self.assertIn("CI001", ids(lint(wf)))


class ScriptInjectionTest(unittest.TestCase):
    def test_title_in_run_is_flagged(self):
        wf = f"""
        on: pull_request
        permissions: {{}}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{{{ github.event.pull_request.title }}}}"
        """
        f = [x for x in lint(wf) if x.rule_id == "CI002"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertIn("pull_request.title", f[0].message)

    def test_env_indirection_is_safe(self):
        wf = """
        on: pull_request
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env:
                  T: ${{ github.event.pull_request.title }}
                run: echo "$T"
              - run: echo "${{ github.sha }}"
        """
        self.assertNotIn("CI002", ids(lint(wf)))

    def test_github_script_is_checked(self):
        wf = f"""
        on: issues
        permissions: {{}}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@{SHA}
                with:
                  script: console.log("${{{{ github.event.issue.body }}}}")
        """
        self.assertIn("CI002", ids(lint(wf)))


class UntrustedCheckoutTest(unittest.TestCase):
    WF = f"""
    on: {{trigger}}
    permissions: {{{{}}}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA}
            with:
              ref: ${{{{{{{{ github.event.pull_request.head.sha }}}}}}}}
    """

    def test_pull_request_target_with_head_checkout(self):
        self.assertIn("CI003", ids(lint(self.WF.format(trigger="pull_request_target"))))

    def test_plain_pull_request_is_fine(self):
        self.assertNotIn("CI003", ids(lint(self.WF.format(trigger="pull_request"))))


class PermissionsTest(unittest.TestCase):
    def test_missing_permissions(self):
        wf = """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: ls
        """
        self.assertIn("CI004", ids(lint(wf)))

    def test_job_level_permissions_are_enough(self):
        wf = """
        on: push
        jobs:
          a:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - run: ls
        """
        self.assertNotIn("CI004", ids(lint(wf)))

    def test_write_all(self):
        wf = """
        on: push
        permissions: write-all
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: ls
        """
        f = [x for x in lint(wf) if x.rule_id == "CI005"]
        self.assertEqual(f[0].severity, Severity.ERROR)


class HardcodedSecretTest(unittest.TestCase):
    def test_github_token_literal(self):
        fake = "ghp_" + "A1b2" * 9  # 36 chars, obviously fake
        wf = f"""
        on: push
        permissions: {{}}
        jobs:
          a:
            runs-on: ubuntu-latest
            env:
              GH: {fake}
            steps:
              - run: ls
        """
        f = [x for x in lint(wf) if x.rule_id == "CI006"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, Severity.ERROR)
        self.assertNotIn(fake, f[0].message)  # never echo the secret

    def test_sensitive_key_literal_vs_secret_ref(self):
        wf = """
        on: push
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: ls
                env:
                  DB_PASSWORD: notasecret123
                  API_TOKEN: ${{ secrets.API_TOKEN }}
        """
        f = [x for x in lint(wf) if x.rule_id == "CI006"]
        self.assertEqual(len(f), 1)
        self.assertIn("DB_PASSWORD", f[0].message)


class MissingCacheTest(unittest.TestCase):
    def _wf(self, with_block, run="npm ci", setup="actions/setup-node"):
        return f"""
        on: push
        permissions: {{}}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: {setup}@{SHA}
                {with_block}
              - run: {run}
        """

    def test_node_without_cache(self):
        self.assertIn("CI007", ids(lint(self._wf("with: {node-version: 20}"))))

    def test_node_with_cache(self):
        self.assertNotIn("CI007", ids(lint(self._wf("with: {cache: npm}"))))

    def test_python_without_cache(self):
        wf = self._wf("with: {python-version: '3.12'}", run="pip install -r r.txt",
                      setup="actions/setup-python")
        self.assertIn("CI007", ids(lint(wf)))

    def test_no_install_no_finding(self):
        self.assertNotIn("CI007", ids(lint(self._wf("with: {node-version: 20}", run="echo hi"))))

    def test_go_caches_by_default(self):
        wf = self._wf("with: {go-version: '1.22'}", run="go test ./...", setup="actions/setup-go")
        self.assertNotIn("CI007", ids(lint(wf)))
        wf = self._wf("with: {cache: false}", run="go test ./...", setup="actions/setup-go")
        self.assertIn("CI007", ids(lint(wf)))

    def test_actions_cache_step_counts(self):
        wf = f"""
        on: push
        permissions: {{}}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-node@{SHA}
              - uses: actions/cache@{SHA}
                with: {{path: ~/.npm, key: npm}}
              - run: npm ci
        """
        self.assertNotIn("CI007", ids(lint(wf)))


class MiscRulesTest(unittest.TestCase):
    def test_self_hosted_on_pr(self):
        wf = """
        on: pull_request
        permissions: {}
        jobs:
          a:
            runs-on: [self-hosted, linux]
            steps:
              - run: ls
        """
        self.assertIn("CI008", ids(lint(wf)))

    def test_unsecure_commands(self):
        wf = """
        on: push
        permissions: {}
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: ls
        """
        self.assertIn("CI009", ids(lint(wf)))

    def test_curl_pipe_shell(self):
        wf = """
        on: push
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: curl -fsSL https://x.example/i.sh | sudo bash
        """
        self.assertIn("CI010", ids(lint(wf)))

    def test_missing_timeout(self):
        wf = CLEAN.replace("    timeout-minutes: 10\n", "")
        self.assertEqual(ids(lint(wf, require_timeout=True)), ["CI011"])

    def test_secrets_inherit(self):
        wf = f"""
        on: push
        permissions: {{}}
        jobs:
          call:
            uses: org/repo/.github/workflows/x.yml@{SHA}
            secrets: inherit
        """
        self.assertIn("CI012", ids(lint(wf)))

    def test_structure_errors(self):
        wf = """
        name: broken
        jobs:
          a:
            steps:
              - name: nothing
        """
        found = ids(lint(wf))
        self.assertGreaterEqual(found.count("CI013"), 3)

    def test_invalid_yaml(self):
        found = lint_text("on: [push\njobs: {", "bad.yml")
        self.assertEqual(ids(found), ["CI000"])


class SuppressionTest(unittest.TestCase):
    def test_inline_ignore_specific_rule(self):
        wf = """
        on: push
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4  # cilint: ignore=CI001
        """
        self.assertNotIn("CI001", ids(lint(wf)))

    def test_ignore_on_previous_comment_line(self):
        wf = """
        on: push
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              # cilint: ignore=CI001
              - uses: actions/checkout@v4
        """
        self.assertNotIn("CI001", ids(lint(wf)))

    def test_ignore_other_rule_does_not_hide(self):
        wf = """
        on: push
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4  # cilint: ignore=CI010
        """
        self.assertIn("CI001", ids(lint(wf)))

    def test_disable_rule(self):
        wf = "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ls\n"
        self.assertNotIn("CI004", ids(lint_text(wf, "w.yml", disabled=["ci004"])))


if __name__ == "__main__":
    unittest.main()
