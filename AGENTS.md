# AGENTS.md

## Commands

- Install: `pip install -e '.[dev,runtime,llm]'` (or `make install`). mypy --strict needs LLM SDK stubs from `.[llm]`.
- `make ci` — full local gate: `lint test typecheck security docs readiness` (default goal). Run this before finishing work.
- `make lint` / `make format` — ruff check + format over `networkforgeai tests tools`. Line length 100, isort rules on.
- `make test` — pytest with coverage; **fails under 90% coverage** (`--cov-fail-under=90`).
- Single test: `python -m pytest tests/test_scope.py -q` (pytest-asyncio in auto mode).
- `make typecheck` — `mypy --strict networkforgeai` over the whole package.
- `make security` — bandit + pip-audit. Bandit excludes `tests/`.
- `make readiness` / `make readiness-strict` — user-readiness gate (`tools/user_readiness.py`).
- `make findings-gate INPUT=path.json` — findings policy gate (`tools/ci_findings_gate.py`); requires INPUT var.

## Testing quirks

- Markers: `integration` (needs local service/binary) and `live_provider` (needs LLM credentials); registered via `--strict-markers`, so don't invent new ones without adding to pyproject.toml.
- Coverage omits `cli.py`, dashboard, and the three LLM adapters — don't chase coverage there.

## Architecture

- Package layout: `networkforgeai/{core,agents,orchestrator,models,sandbox,reporting,integrations,interface,tools}`; CLI entry point `networkforgeai.cli:main`.
- Core safety invariant: **all offensive actions go through the human approval gateway and fail closed**; every invocation requires an explicit allow-list scope (`core/scope.py`). Tests (`test_phase8_safety.py`) enforce approval fail-closed behavior — preserve it.
- Execution happens in a per-scan Docker sandbox (`sandbox/runner.py`, docker-compose.yml); CI never scans external targets.

## Config / env

- Settings come from env vars (pydantic-settings), see `.env.example`: `TARGET_SCOPE` (comma-separated), `APPROVAL_MODE` (strict|moderate|lenient), `DASHBOARD_AUTH_TOKEN`, `LITELLM_MODEL`.
- Python >=3.10; CI runs 3.10–3.13. Install with `pip install -e '.[dev,runtime,llm]'`.

## CI notes

- `.github/workflows/ci.yml` also builds the wheel and smoke-tests it from a clean venv (`--version`, `--list-tools`, `--validate-config`, dry-run scan) — keep CLI flags working standalone after wheel install.
- `make docs` runs `tools/ci_docs_audit.py`, which audits documentation links/content; update docs when changing behavior it checks.
