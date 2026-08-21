# CI/CD Integration

The production CI workflow runs:

1. Ruff lint and formatting checks.
2. Pytest with coverage.
3. Strict MyPy checking for the typed safety, reporting, integration, and package surfaces.
4. Bandit and dependency auditing.
5. Markdown link/documentation audits.
6. Docker Compose configuration validation.
7. The user-readiness gate.

The strict MyPy gate currently covers the maintained typed core surfaces. Legacy
LLM adapters, agent implementations, and dashboard modules remain outside the
gate while they are incrementally typed.

The current minimum coverage gate is 90%. It is enforced identically in CI and
the local `make test` target.

Run the same checks locally with:

```bash
make ci
```

The readiness gate does not perform network scans or require LLM credentials. It
verifies compilation, CLI help/version/tool inventory, safe dry-run behavior,
report path containment, configuration validation, documentation links, report
generation, authenticated read-only dashboard behavior, scope denial, approval
fail-closed behavior, secret-free example configuration, and deployment
configuration. Optional checks are explicitly reported as skipped when their
runtime dependency is unavailable; CI installs the full runtime set.

For deployment policy enforcement, run the findings gate against a JSON or SARIF
report:

```bash
make findings-gate INPUT=./scans/<scan-id>/findings.json
```

The default gate blocks high and critical findings unless they are marked
remediated or false-positive.
