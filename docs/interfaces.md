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

The dashboard requires `Authorization: Bearer <token>` for all endpoints except
`/health` and the operator console shell:

- `GET /health` — liveness response.
- `GET /` — dependency-free operator console (static shell; no data without a token).
- `GET /reports` — relative report paths.
- `GET /reports/{path}` — report content, with JSON decoded when applicable.
- `GET /scans` — persisted scan summaries.
- `GET /scans/{scan_id}` — persisted scan state.
- `GET /scans/{scan_id}/findings` — persisted findings for one scan.

When a live `ScanOrchestrator` is attached via
`create_app(orchestrator=...)`, operator endpoints are enabled; without an
attached scan they return `503` (fail closed):

- `GET /agents` — live agent statuses and scan status.
- `GET /approvals` — pending approval queue and emergency-stop state.
- `POST /approvals/{request_id}/approve|reject` — audited gateway decisions.
- `POST /scan/pause|resume|stop` — steering controls mapped to orchestrator
  lifecycle methods.

Approval decisions made through the dashboard flow through the same human
approval gateway and audit trail as every other path. The dashboard never
starts scans.
