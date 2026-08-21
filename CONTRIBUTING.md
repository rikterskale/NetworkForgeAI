# Contributing

Thanks for contributing to NetworkForgeAI. This project is an authorized-use
security tool with hard safety invariants — please read this page fully before
your first change.

## Safety invariants (non-negotiable)

- **All offensive actions go through the human approval gateway and fail
  closed.** Never add a code path that executes HIGH/CRITICAL actions without
  an explicit approval decision.
- **Every invocation requires an explicit allow-list scope.** Scope checks
  happen before any action; exclusions always win.
- **Host execution is opt-in only.** Default execution path is the Docker
  sandbox (`--network none`, dropped capabilities).
- Changes to `core/approval_gateway.py`, `core/scope.py`, or the safety tests
  in `tests/test_phase8_safety.py` are security-sensitive: expect extra review.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e '.[dev,runtime,llm]'
```

The `[llm]` extra provides SDK type stubs required by strict MyPy.

## The quality gate

Run the full gate before finishing any work:

```bash
make ci        # lint + test + typecheck + security + docs + readiness
```

| Gate | Command | Notes |
|------|---------|-------|
| Lint/format | `make lint` / `make format` | ruff, line length 100, isort rules |
| Tests | `make test` | pytest; **fails under 90% coverage** |
| Single test | `python -m pytest tests/test_scope.py -q` | asyncio_mode is auto |
| Typecheck | `make typecheck` | `mypy --strict networkforgeai` (whole package) |
| Security | `make security` | bandit + pip-audit |
| Docs | `make docs` | link/content audit (`tools/ci_docs_audit.py`) |

## Testing conventions

- Markers are strict: `integration` (needs a local service/binary) and
  `live_provider` (needs LLM credentials). Register new markers in
  `pyproject.toml` before using them.
- Coverage omits `cli.py`, the dashboard, and the three provider adapters —
  don't chase coverage there.
- New safety-relevant behavior needs a fail-closed test (prove it refuses to
  act without approval/scope/sandbox).

## Code conventions

- Full strict typing on everything under `networkforgeai/`; new modules must
  pass `mypy --strict` or CI fails.
- Dependency-light: avoid adding runtime dependencies. Use the standard library
  unless there is no reasonable alternative.
- No secrets in code, logs, or reports. Evidence marked `sensitive` is redacted
  by default — keep it that way.
- Update documentation when changing behavior the docs audit checks, and update
  [CAPABILITY_REGISTER.md](CAPABILITY_REGISTER.md) at the end of a phase of work.

## Submitting changes

1. Create a feature branch.
2. Make your change with tests.
3. Run `make ci` locally until green.
4. Open a pull request against `main`; CI runs the same gates plus a clean
   wheel-install smoke test — keep CLI flags working standalone after install.
