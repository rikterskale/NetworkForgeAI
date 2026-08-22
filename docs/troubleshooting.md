# Troubleshooting guide

Start with safe diagnostics:

```bash
python --version
python -m networkforgeai.cli --version
python -m networkforgeai.cli --help
python -m networkforgeai.cli --list-tools
python tools/user_readiness.py
```

Do not solve an error by widening scope, disabling approvals, or enabling host
execution until you understand it and have operator authorization.

## Installation problems

### `python3: command not found`

Install Python 3.10+ through your operating system package manager or from
[python.org](https://www.python.org/downloads/). On Windows, try `py` instead of
`python3`.

### `No module named networkforgeai`

Activate the project environment and install from the repository root:

```bash
source .venv/bin/activate
python -m pip install -e '.[runtime,dev]'
```

### `No module named pytest`, `ruff`, or `mypy`

Install development dependencies:

```bash
python -m pip install -e '.[dev,runtime]'
```

### System Python refuses pip installation

Some Linux distributions mark system Python as externally managed. Do not force
packages into it. Use a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,runtime]'
```

## Configuration problems

### `TARGET_SCOPE` is empty

Set an authorized scope in `.env` or supply a one-run scope:

```bash
TARGET_SCOPE=app.example.test python -m networkforgeai.cli --validate-config
```

The CLI scan path still requires `--scope`.

### `REPORT_FORMATS` fails to parse

Use JSON array syntax:

```dotenv
REPORT_FORMATS=["markdown","json","csv","sarif"]
```

Do not use a bare comma-separated string.

### Dashboard returns unauthorized

Use the same token in the server environment and request header:

```bash
export DASHBOARD_AUTH_TOKEN='your-random-token'
curl -H "Authorization: Bearer $DASHBOARD_AUTH_TOKEN" \
  http://127.0.0.1:8080/reports
```

`/health` is the only unauthenticated endpoint. Never paste the token into a
shared URL or commit it.

### Provider errors

Confirm the matching key and provider name. Start with a local dry run to separate
CLI/scope problems from provider problems. Live calls also require the provider
SDK installed through the optional dependency set.

## Docker and sandbox problems

### Docker is not running

Start Docker Desktop or the Docker service, then verify:

```bash
docker version
docker compose config --quiet
```

Do not switch to `--host-execution` just to bypass a missing daemon.

### Sandbox image is missing

```bash
export NETWORKFORGE_SANDBOX_IMAGE=your-approved-security-tools:tag
docker image inspect "$NETWORKFORGE_SANDBOX_IMAGE"
```

The image must contain the external binary for the selected tool.

### A tool binary is not found

The Python integration is a command builder/parser. Install the binary in the
approved sandbox image and confirm its version there. Do not install unreviewed
offensive tooling directly on a production host.

### Sandbox image and host architecture do not match

Verify the image architecture and the tool versions before scanning:

```bash
docker image inspect "$NETWORKFORGE_SANDBOX_IMAGE" --format '{{.Architecture}}/{{.Os}}'
docker run --rm "$NETWORKFORGE_SANDBOX_IMAGE" nmap --version
```

On Apple Silicon or another non-amd64 host, use an approved multi-architecture
image or explicitly validate the required emulation policy. Do not silently
replace the sandbox with host execution.

### A scan completes with partial results

The `partial` scan status means one or more agent phases failed while other
phases produced results. Preserve `scan_state.json`, inspect its `phase_errors`
entries, and rerun only after resolving the named tool, model, or sandbox issue.
Treat the report as incomplete until every required phase is accounted for.

## Scope and approval problems

### A valid-looking target is denied

Check spelling, allow-list coverage, quoted wildcards, and exclusions. Test scope
matching without scanning:

```bash
python -c 'from networkforgeai.core.scope import ScopePolicy; print(ScopePolicy(["example.test"]).contains("api.example.test"))'
```

### An approval is pending

Review the target, action, risk, expiry, and evidence. Approve only an action
covered by authorization. Reject it if scope, impact, or timing is unclear.

### Emergency stop is active

The emergency stop intentionally cancels pending approvals and blocks new ones.
Preserve the audit record and reset only after an operator authorizes resumption.

## Reporting problems

### No reports appear

Confirm the output directory:

```bash
python -m networkforgeai.cli --list-reports --output-dir ./reports
find ./reports -maxdepth 3 -type f -print
```

The CLI defaults to `./scans`, while the dashboard commonly uses `./reports`.

### Report path is rejected

The path must remain below `--output-dir`. Use `scan-id/report.md`, not an
absolute path or `../` traversal.

### Sensitive data appears in evidence

Stop sharing the report, restrict its permissions, and follow your engagement
handling procedure. Treat all reports as sensitive security artifacts.

## CI and developer checks

```bash
make ci
```

If `make` cannot find tools, activate `.venv` first. The CI workflow also runs
strict MyPy on the maintained typed surfaces; the legacy typing backlog is tracked
in the capability register.

## When to stop and ask for help

Stop rather than experimenting if the target scope is uncertain, a command could
affect availability or data, approval state and audit records disagree, a retry
could hit the wrong target, or a report may contain credentials or regulated data.
Preserve the command, error text, version, configuration keys used (not their
secret values), and relevant audit identifiers.
