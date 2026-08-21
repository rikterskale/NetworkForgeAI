# Interface Guide

## CLI

Scan operations retain the explicit target and scope requirements:

```bash
networkforgeai --target example.com --scope example.com --tool nmap --dry-run
```

Operator support commands do not require a target:

```bash
networkforgeai --list-tools
networkforgeai --list-reports --output-dir ./scans
networkforgeai --show-report scan-id/report.md --output-dir ./scans
networkforgeai --validate-config
networkforgeai --version
```

Report reads are restricted to the configured output directory. A path that
attempts to escape that directory is rejected.

## Dashboard API

The dashboard is read-only and requires `Authorization: Bearer <token>` for
all endpoints except `/health`:

- `GET /health` — liveness response.
- `GET /reports` — relative report paths.
- `GET /reports/{path}` — report content, with JSON decoded when applicable.
- `GET /scans` — persisted scan summaries.
- `GET /scans/{scan_id}` — persisted scan state.

The dashboard does not start scans or approve actions. Approval and execution
remain controlled by the host-side gateway.
