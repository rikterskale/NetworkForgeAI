# CI/CD Integration

The production CI workflow runs:

1. Ruff lint and formatting checks.
2. Pytest with coverage.
3. Strict MyPy checking for the typed safety, reporting, integration, and package surfaces.
4. Bandit and dependency auditing.
5. Markdown link/documentation audits.
6. Docker Compose configuration validation.
7. A clean wheel-install smoke test using the installed `networkforgeai`
   command.
8. The strict user-readiness gate.

The strict MyPy gate currently covers the maintained typed core surfaces. Legacy
LLM adapters, agent implementations, and dashboard modules remain outside the
gate while they are incrementally typed.

The current minimum coverage gate is 90%. It is enforced identically in CI and
the local `make test` target.

Run the same checks locally with:

```bash
make ci
```

The package-install job builds a wheel, installs it into a brand-new virtual
environment outside the checkout, runs `pip check`, and exercises version, help,
tool inventory, configuration validation, and a safe dry run through the
installed console command. This catches missing package files, broken metadata,
and entry-point failures that editable installs can hide.

The readiness report also requires the installed `networkforgeai` entry point to
exist. This prevents a green source-checkout build from hiding a broken command
that a newly installed user would actually run.

The readiness gate does not perform network scans or require LLM credentials. It
verifies compilation, beginner-facing CLI safety controls, CLI help/version/tool
inventory, safe dry-run behavior, rejection of missing or out-of-scope targets,
report path containment, configuration validation, documentation links, report
generation, authenticated read-only dashboard behavior, scope denial, approval
fail-closed behavior, safe example configuration, and deployment configuration.
CI also runs `pip check` to catch broken installed dependencies. CI invokes the
readiness tool with `--strict`, so any optional check that is skipped fails the
release gate. Local runs remain best-effort by default; use
`python tools/user_readiness.py --strict --json` to reproduce the production
review locally.

For deployment policy enforcement, run the findings gate against a JSON or SARIF
report:

```bash
make findings-gate INPUT=./scans/<scan-id>/findings.json
```

The default gate blocks high and critical findings unless they are marked
remediated or false-positive.

## GitLab CI

A parity template for GitLab pipelines ships at
`templates/gitlab-ci-networkforgeai.yml`. It runs the same stages as GitHub
Actions: lint, tests (with the 90% coverage gate), strict MyPy, Bandit +
pip-audit, documentation audit, and the findings policy gate.

Include it from your project's `.gitlab-ci.yml`:

```yaml
include:
  - project: your-group/your-repo
    ref: main
    file: templates/gitlab-ci-networkforgeai.yml
```

Point the findings gate at your scan output by overriding the variable:

```yaml
findings-gate:
  variables:
    FINDINGS_INPUT: "scans/<scan-id>/findings.json"
```

Like the GitHub workflow, the gate fails the pipeline when unremediated high or
critical findings are present.
