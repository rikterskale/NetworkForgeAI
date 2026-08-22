# Installation and first safe run

This guide is written for someone who has not used NetworkForgeAI before. It
walks through installation, a harmless dry run, configuration validation, and
the checks to perform before any real authorized testing.

## 0. Before you begin

NetworkForgeAI is a security-testing tool. Only test systems that you own or
have written permission to test. Before installing, identify:

1. The exact hostname, IP address, URL, or CIDR range you are authorized to test.
2. The dates and actions allowed by the authorization.
3. Where reports and audit records may be stored.
4. Which human operator will approve higher-risk actions.

Do not use a public target as a practice target. Use a local lab, a cyber-range
target, or a system covered by written authorization.

## 1. Install prerequisites

You need:

- Python 3.10 or newer
- Git
- A terminal
- Docker Desktop or Docker Engine for sandboxed tool execution (not needed for
  installation, help, configuration validation, or dry runs)
- An LLM provider key only if you want model-backed analysis

Check Python and Git:

```bash
python3 --version
git --version
```

On Debian or Ubuntu, install the common Python packages if needed:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git
```

On macOS, install Python and Git with Homebrew if they are not already present:

```bash
brew install python git
```

On Windows, install Python from [python.org](https://www.python.org/downloads/)
and select **Add Python to PATH** during installation. Run the commands below
in PowerShell; use `py` in place of `python3` when necessary.

## 2. Download the repository

Replace the repository URL with the URL provided by your organization:

```bash
git clone <repository-url>
cd NetworkForgeAI
```

Confirm that you are in the project directory:

```bash
ls
```

You should see `pyproject.toml`, `README.md`, `networkforgeai/`, `tests/`, and
`docs/`.

## 3. Create an isolated Python environment

An isolated environment prevents this project from changing packages used by
other Python applications.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

After activation, your prompt normally starts with `(.venv)`. Upgrade pip and
install the project for normal use:

```bash
python -m pip install --upgrade pip
python -m pip install '.[runtime]'
```

The install creates the `networkforgeai` command inside `.venv`. Contributors
who need tests and code-quality tools can install the larger developer extra:

```bash
python -m pip install '.[runtime,dev]'
```

Contributors working on the LLM adapter layer (or running `make typecheck`)
also need the optional provider SDKs, which supply MyPy type stubs:

```bash
python -m pip install '.[runtime,dev,llm]'
```

On Windows PowerShell, activate with:

```powershell
.venv\Scripts\Activate.ps1
```

If activation is unavailable, use the environment’s Python explicitly:

```bash
.venv/bin/python -m pip install '.[runtime]'
```

## 4. Create a private configuration file

Copy the example file. The `.env` file is intentionally ignored by Git; never
commit it.

```bash
cp .env.example .env
```

Open `.env` and make these safe first changes:

```dotenv
TARGET_SCOPE=your-authorized-host.example
APPROVAL_MODE=strict
BLOCK_DESTRUCTIVE_ACTIONS=true
DASHBOARD_AUTH_TOKEN=generate-a-long-random-value
REPORT_OUTPUT_DIR=./reports
```

Generate a dashboard token without putting it in shell history:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the output into `.env` after `DASHBOARD_AUTH_TOKEN=`. See the
[configuration reference](configuration.md) for every setting and valid value.

## 5. Verify the installation

Run these commands from the repository root:

```bash
networkforgeai --version
networkforgeai --help
networkforgeai --list-tools
networkforgeai --validate-config
```

The tool list should show the currently registered integrations. Configuration validation requires
a non-empty `TARGET_SCOPE`; it does not scan anything.

Run the local readiness checks:

```bash
python tools/user_readiness.py
```

For the complete developer/CI suite, run:

```bash
make ci
```

If your shell cannot find project tools such as `ruff`, activate `.venv` first or
use `.venv/bin/python` explicitly.

## 6. Perform a harmless dry run

A dry run builds the command but does not execute the external tool. Use a target
that is explicitly authorized in your scope:

```bash
networkforgeai \
  --target your-authorized-host.example \
  --scope your-authorized-host.example \
  --tool nmap \
  --dry-run
```

The output should be JSON and contain a command plus a `[DRY RUN]` message. If
the target is not covered by `--scope`, the command must stop with an error.

## 7. Run a real sandboxed tool only when authorized

Sandboxed execution requires Docker and a controlled image containing the tool
binary. Set the image explicitly:

```bash
export NETWORKFORGE_SANDBOX_IMAGE=your-approved-security-tools:tag
docker image inspect "$NETWORKFORGE_SANDBOX_IMAGE"
```

Then run a low-risk operation against an authorized target. Keep strict approval
mode enabled and review the output before continuing. If the image is missing,
NetworkForgeAI fails closed instead of silently executing on the host.

The image must contain the selected binary at a known, reviewed version. The
repository image is a development baseline and does not include every registered
integration; maintain an approved image compatibility matrix for production.

Do not use `--host-execution` in production. It disables Docker sandboxing and is
provided only for explicitly authorized development environments.

## 8. Optional: start the read-only dashboard

The dashboard displays persisted reports and scan summaries. It does not start
scans or approve actions.

```bash
mkdir -p reports
export DASHBOARD_AUTH_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export REPORT_OUTPUT_DIR=./reports
python -m uvicorn networkforgeai.interface.dashboard:app \
  --host 127.0.0.1 \
  --port 8080
```

Visit `http://127.0.0.1:8080/health` to check liveness. Protected endpoints
require a bearer token. See [interfaces](interfaces.md) for API examples.

## 9. Optional: use Docker Compose

Validate Compose without starting services:

```bash
docker compose config --quiet
```

Start the dashboard stack only after reviewing `.env` and mounted report paths:

```bash
docker compose up --build dashboard
```

Stop it with:

```bash
docker compose down
```

The optional Caido service is behind the `with-proxy` profile and is not needed
for the basic workflow.

## 10. Installation checklist

- [ ] Written authorization and exact target scope are recorded.
- [ ] `.venv` is active or every command uses `.venv/bin/python`.
- [ ] `.env` exists and is not tracked by Git.
- [ ] `TARGET_SCOPE` contains only authorized targets.
- [ ] `APPROVAL_MODE=strict` and destructive actions remain blocked.
- [ ] `--validate-config` succeeds.
- [ ] The dry run succeeds without contacting a target.
- [ ] Docker and the approved sandbox image are available before real execution.
- [ ] Reports and audit logs have an approved storage location.

## Next steps

1. [Configuration reference](configuration.md)
2. [CLI workflows](cli-reference.md)
3. [Approval system](approval-system.md)
4. [Reporting](reporting.md)
5. [Troubleshooting](troubleshooting.md)
