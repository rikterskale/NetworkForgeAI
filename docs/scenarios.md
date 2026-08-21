# Example scan scenarios

These scenarios are safe practice exercises for operators. Every scenario uses a
target you control. Do not run them against systems you do not own or lack
written authorization to test.

Each scenario assumes the [installation](installation.md) is complete and commands
run from the repository root with `.venv` active.

## Scenario 0: Verify nothing leaks outside scope

Purpose: confirm the fail-closed behavior before any real work.

```bash
networkforgeai \
  --target unauthorized.example \
  --scope app.example.test \
  --tool nmap \
  --dry-run
```

Expected result: the command exits with an error and never contacts a target.
This is what should happen; if it does not, stop and file a bug.

## Scenario 1: First dry run against your own host

Purpose: learn the interface with zero target contact.

1. Pick a hostname you own (below, `lab.example.test`).
2. Run:

```bash
networkforgeai \
  --target lab.example.test \
  --scope lab.example.test \
  --tool nmap \
  --dry-run
```

3. Inspect the JSON output: it shows the exact command that *would* run.
4. Confirm no packets left your machine (the `[DRY RUN]` marker means no tool
   executed).

## Scenario 2: Wildcard scope with exclusions

Purpose: practice scoping a subdomain range while carving out sensitive hosts.

```bash
networkforgeai \
  --target staging.lab.example.test \
  --scope '*.lab.example.test' \
  --exclude admin.lab.example.test \
  --tool nikto \
  --dry-run
```

Try changing `--target` to `admin.lab.example.test`. The exclusion must deny it
even though it matches the wildcard. Quote wildcards so the shell does not expand
them.

## Scenario 3: Sandbox reconnaissance of a local lab VM

Purpose: first real execution, inside Docker, against a machine you own.

Prerequisites:

- Docker running.
- An approved sandbox image containing nmap:
  `export NETWORKFORGE_SANDBOX_IMAGE=your-approved-security-tools:tag`
- A lab target on your network, for example `192.168.56.10`.

```bash
networkforgeai \
  --target 192.168.56.10 \
  --scope 192.168.56.0/24 \
  --tool nmap \
  --output-dir ./scans
```

Keep `APPROVAL_MODE=strict`. If approval is required, approve only after reading
the proposed command. Results land under `./scans/<scan-id>/`.

## Scenario 4: Full agent workflow in an isolated cyber range

Purpose: exercise orchestration end to end where blast radius is zero.

Use an isolated cyber-range network (for example, a deliberately vulnerable VM
such as Metasploitable on a host-only virtual network). Never point this at a
shared or production network.

```bash
networkforgeai \
  --target 192.168.99.10 \
  --scope 192.168.99.0/24 \
  --provider local \
  --output-dir ./scans \
  --orchestrate
```

Watch the live status display, respond to approval prompts deliberately, then
review outputs:

```bash
networkforgeai --list-reports --output-dir ./scans
networkforgeai --show-report <scan-id>/report.md --output-dir ./scans
```

Model suggestions are advisory only; scope checks and human approval still gate
every action.

## Scenario 5: Read-only dashboard review

Purpose: review persisted results through the operator console without touching
a target.

```bash
mkdir -p reports
export DASHBOARD_AUTH_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export REPORT_OUTPUT_DIR=./reports
python -m uvicorn networkforgeai.interface.dashboard:app --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080/health`, then the console at `http://127.0.0.1:8080/`.
Protected endpoints require the bearer token; see [interfaces](interfaces.md).

## Building your own scenarios

- Start every new workflow as a `--dry-run`.
- Scope narrowly: one host before a CIDR, explicit `--exclude` for anything sensitive.
- Keep `APPROVAL_MODE=strict` until you can argue why a lower mode is safe for
  your environment.
- Treat all reports as sensitive evidence; store them in an approved location.

See also: [CLI reference](cli-reference.md), [approval system](approval-system.md),
[configuration reference](configuration.md).
