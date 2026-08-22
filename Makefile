.DEFAULT_GOAL := ci
PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e '.[dev,runtime,llm]'

format:
	ruff format networkforgeai tests tools

lint:
	ruff check networkforgeai tests tools
	ruff format --check networkforgeai tests tools

test:
	$(PYTHON) -m pytest -q --cov=networkforgeai --cov-report=term-missing --cov-fail-under=90

typecheck:
	$(PYTHON) -m mypy --strict networkforgeai

security:
	bandit -q -r networkforgeai -ll
	pip-audit

docs:
	$(PYTHON) tools/ci_docs_audit.py
	$(PYTHON) tools/generate_cli_docs.py --check

docs-generate:
	$(PYTHON) tools/generate_cli_docs.py

findings-gate:
	@test -n "$(INPUT)" || (echo "Usage: make findings-gate INPUT=path/to/findings.json" && exit 2)
	$(PYTHON) tools/ci_findings_gate.py "$(INPUT)" --json

readiness:
	$(PYTHON) tools/user_readiness.py

readiness-strict:
	$(PYTHON) tools/user_readiness.py --strict --json

ci: lint test typecheck security docs readiness
