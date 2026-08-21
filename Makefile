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
	pytest -q --cov=networkforgeai --cov-report=term-missing --cov-fail-under=90

security:
	bandit -q -r networkforgeai -ll
	pip-audit

docs:
	$(PYTHON) tools/ci_docs_audit.py

readiness:
	$(PYTHON) tools/user_readiness.py

ci: lint test security docs readiness
