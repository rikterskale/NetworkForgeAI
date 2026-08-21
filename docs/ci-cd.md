# CI/CD Integration

The production CI workflow runs:

1. Ruff lint and formatting checks.
2. Pytest with coverage.
3. Bandit and dependency auditing.
4. Markdown link/documentation audits.
5. Docker Compose configuration validation.
6. The user-readiness gate.

The current minimum coverage gate is 50%. It is intentionally enforced in CI and
should be raised as integration and provider-mocking coverage grows.

Run the same checks locally with:

```bash
make ci
```

The readiness gate does not perform network scans or require LLM credentials. It
verifies safe defaults, CLI behavior, report generation, scope denial, approval
fail-closed behavior, and deployment configuration.
