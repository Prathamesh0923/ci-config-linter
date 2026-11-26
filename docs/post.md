Most GitHub Actions security bugs are one line of YAML, so I built a linter that points at that exact line.

CI Config Linter is a small offline Python CLI that reads `.github/workflows/*.yml` and reports 14 rules: untrusted event data like `github.event.pull_request.title` interpolated into `run:` scripts, `pull_request_target` workflows that check out the PR head, actions pinned to a branch or tag instead of a commit SHA, `permissions: write-all`, hardcoded tokens, `curl | bash`, and setup-node/python/go steps with no dependency cache.

The interesting part was line numbers. PyYAML's normal output is plain dicts and lists, so the position information is gone by the time rules run. I subclassed `SafeLoader` and swapped in constructors that build a dict and list type which store the source line of every key and list item. Every finding then carries file, line, rule ID and job name, and inline `# cilint: ignore=CI010` comments work. One YAML 1.1 quirk to handle: a bare `on:` key is parsed as boolean `True`.

Output is text, JSON, or GitHub `::error` annotations. 42 unittest tests, only dependency is PyYAML.

#GitHubActions #DevSecOps #Python #CICD #SupplyChainSecurity
