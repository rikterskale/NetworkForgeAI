# CI/CD Integration

The production CI workflow runs:

1. Ruff lint and formatting checks.
2. Pytest with coverage.
3. Bandit and dependency auditing.
4. Markdown link/documentation audits.
5. Docker Compose configuration validation.
6. The user-readiness gate.

The current minimum coverage gate is 75%. It is enforced identically in CI and
the local `make test` target.

Run the same checks locally with:

```bash
make ci
```

The readiness gate does not perform network scans or require LLM credentials. It
verifies safe defaults, CLI behavior, report generation, scope denial, approval
fail-closed behavior, and deployment configuration.
