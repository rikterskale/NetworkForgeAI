# CLI reference and beginner workflows

The installed command is `networkforgeai`. The module form works everywhere and
is used throughout this guide:

```bash
python -m networkforgeai.cli
```

Run commands from the repository root with the virtual environment active.

## Get help

```bash
python -m networkforgeai.cli --help
python -m networkforgeai.cli --version
```

## Read-only commands

These commands do not start a scan:

```bash
python -m networkforgeai.cli --list-tools
python -m networkforgeai.cli --list-reports --output-dir ./reports
python -m networkforgeai.cli --show-report scan-id/report.md --output-dir ./reports
python -m networkforgeai.cli --validate-config
```

`--show-report` rejects paths that escape `--output-dir`, such as `../secret.txt`.

## Common option reference

| Option | Meaning |
|---|---|
| `--target VALUE` | Exact authorized target for this invocation |
| `--scope VALUE` | Allowed host, IP, wildcard, or CIDR; repeatable |
| `--exclude VALUE` | Explicitly excluded target; repeatable |
| `--mode strict\|moderate\|lenient` | Approval policy; default is `strict` |
| `--tool NAME` | Run one registered tool |
| `--dry-run` | Build the command without executing it |
| `--host-execution` | Disable Docker sandboxing; development use only |
| `--output-dir PATH` | Scan/report directory; default is `./scans` |
| `--orchestrate` | Execute the basic agent workflow after startup |
| `--provider NAME` | Select `openai`, `anthropic`, `google`, `local`, or `litellm` |

Every scan operation needs both `--target` and at least one `--scope`. The target
must match the scope after exclusions are applied.

## Workflow A: inspect tools

```bash
python -m networkforgeai.cli --list-tools
```

The output includes each tool’s name, risk level, and category. Availability does
not mean an external binary is installed or execution is authorized.

## Workflow B: safe dry run

```bash
python -m networkforgeai.cli \
  --target app.example.test \
  --scope app.example.test \
  --tool nmap \
  --dry-run
```

The scope is checked, the command is constructed, no scanner is launched, and a
JSON result is printed. Use dry runs when learning the interface or reviewing a
proposed command with an operator.

## Workflow C: sandboxed execution

Only do this for a written-authorized target and approved tool image:

```bash
export NETWORKFORGE_SANDBOX_IMAGE=your-approved-security-tools:tag
docker image inspect "$NETWORKFORGE_SANDBOX_IMAGE"
python -m networkforgeai.cli \
  --target app.example.test \
  --scope app.example.test \
  --tool nmap \
  --output-dir ./scans
```

If Docker or the image is unavailable, execution fails closed. Do not use
`--host-execution` in production; it is for explicitly authorized development.

## Workflow D: exclusions

```bash
python -m networkforgeai.cli \
  --target app.example.test \
  --scope '*.example.test' \
  --exclude admin.example.test \
  --tool nmap \
  --dry-run
```

Quote wildcard values so the shell does not expand them. An excluded target is
denied even when it matches an allowed entry.

## Workflow E: basic agent workflow

Add `--orchestrate` only when you understand the action sequence and have provider
configuration:

```bash
python -m networkforgeai.cli \
  --target app.example.test \
  --scope app.example.test \
  --provider local \
  --output-dir ./scans \
  --orchestrate
```

For hosted providers, configure the matching API key first. Model output is a
recommendation, not authorization; scope and approval controls still apply.

## Workflow F: inspect reports

```bash
python -m networkforgeai.cli --list-reports --output-dir ./scans
python -m networkforgeai.cli \
  --show-report scan-id/report.md \
  --output-dir ./scans
```

Treat reports as potentially sensitive evidence.

## Exit codes

- `0`: command completed successfully.
- `1`: a tool or scan-level operation reported failure.
- `2`: argument parsing or required scan arguments failed.

## Common mistakes

### “--target and --scope are required”

Add both values, for example `--target app.example.test --scope app.example.test`.

### “Target is outside the explicitly supplied scope”

The target does not match the allow-list or is excluded. Confirm the written
authorization instead of broadening scope reflexively.

### “approval gateway” or “execution was not approved”

The operation needs human approval. Use the approved gateway and obtain a human
decision; do not bypass the tool wrapper.

### “NETWORKFORGE_SANDBOX_IMAGE is required”

Set the approved image and verify it with `docker image inspect`.

Read [troubleshooting](troubleshooting.md) before changing safety settings.
