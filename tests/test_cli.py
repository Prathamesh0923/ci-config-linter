import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ci_linter.cli import main

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def test_secure_example_passes(self):
        code, out, _ = run(str(EXAMPLES / "secure"))
        self.assertEqual(code, 0, out)
        self.assertIn("0 error(s), 0 warning(s), 0 info", out)

    def test_insecure_example_fails_with_expected_rules(self):
        code, out, _ = run(str(EXAMPLES / "insecure"), "--format", "json")
        self.assertEqual(code, 1)
        data = json.loads(out)
        rules = {f["rule_id"] for f in data["findings"]}
        for expected in ("CI001", "CI002", "CI003", "CI005", "CI006",
                         "CI007", "CI008", "CI009", "CI010"):
            self.assertIn(expected, rules)
        self.assertGreater(data["summary"]["error"], 0)

    def test_min_severity_and_fail_on(self):
        code, out, _ = run(str(EXAMPLES / "insecure"), "--format", "json",
                           "--min-severity", "error", "--fail-on", "never")
        self.assertEqual(code, 0)
        sev = {f["severity"] for f in json.loads(out)["findings"]}
        self.assertEqual(sev, {"error"})

    def test_github_format(self):
        _, out, _ = run(str(EXAMPLES / "insecure"), "--format", "github")
        self.assertTrue(out.startswith("::"))
        self.assertIn("title=CI00", out)

    def test_discovers_dot_github_workflows(self):
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            (wf_dir / "a.yml").write_text((EXAMPLES / "secure" / "ci.yml").read_text())
            (Path(tmp) / "other.yml").write_text("not: a workflow\n")
            code, out, _ = run(tmp)
            self.assertEqual(code, 0, out)
            self.assertIn("1 file(s) checked", out)

    def test_missing_path(self):
        code, _, err = run("/definitely/not/here")
        self.assertEqual(code, 2)
        self.assertIn("No such file", err)

    def test_list_rules(self):
        code, out, _ = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("CI001", out)
        self.assertIn("CI007", out)


if __name__ == "__main__":
    unittest.main()
