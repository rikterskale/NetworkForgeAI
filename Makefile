.DEFAULT_GOAL := ci
PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e '.[dev,runtime]'

format:
	ruff format networkforgeai tests tools

lint:
	ruff check networkforgeai tests tools
	ruff format --check networkforgeai tests tools

test:
	$(PYTHON) -m pytest -q --cov=networkforgeai --cov-report=term-missing --cov-fail-under=90

typecheck:
	$(PYTHON) -m mypy --strict networkforgeai/__init__.py networkforgeai/core/scope.py networkforgeai/core/approval_gateway.py networkforgeai/reporting/models.py networkforgeai/reporting/generators.py networkforgeai/integrations/webhooks.py networkforgeai/sandbox/runner.py

security:
	bandit -q -r networkforgeai -ll
	pip-audit

docs:
	$(PYTHON) tools/ci_docs_audit.py

findings-gate:
	@test -n "$(INPUT)" || (echo "Usage: make findings-gate INPUT=path/to/findings.json" && exit 2)
	$(PYTHON) tools/ci_findings_gate.py "$(INPUT)" --json

readiness:
	$(PYTHON) tools/user_readiness.py

ci: lint test typecheck security docs readiness
