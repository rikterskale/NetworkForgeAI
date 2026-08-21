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
`/health` and the operator console shell. Two roles exist:

- **Operator** (`DASHBOARD_AUTH_TOKEN`): full access, including approvals and steering.
- **Viewer** (`DASHBOARD_VIEWER_TOKEN`, optional): read-only access to `/reports`,
  `/scans`, and `/agents`; approval and steering endpoints return `401`.

Read-only surfaces:

- `GET /health` — liveness response.
- `GET /` — dependency-free operator console (static shell; no data without a token).
  The console is a tabbed GUI: **Live** (steering, agent graph, agent status,
  approval queue), **Scans & findings** (persisted scans with click-through
  findings view), and **Reports** (browse and view generated report files).
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

## Terminal UI (TUI)

`networkforgeai.interface.tui` provides dependency-free terminal surfaces for
operators who do not use the dashboard:

- **`TUIDisplay`** — progress bars (`display.progress(done, total)`) and aligned
  tables (`display.table(headers, rows)`), with ANSI color when the stream is a
  TTY.
- **`LogStreamPanel`** — `panel.log(source, message)` prints timestamped lines
  tagged `INFO`, `ERROR`, `WARN`, or `APPROVAL`.
- **`InteractiveMenu`** — number-key menu; pass `items=[(label, action), ...]`.
  In non-interactive sessions the menu renders but is disabled.
- **`ApprovalDialog`** — boxed approval dialog registered like
  `ApprovalPrompt`: `gateway.register_callback("tui", dialog)`. Any input
  failure rejects the request, and non-interactive sessions leave requests
  PENDING (fail closed).

```python
from networkforgeai.interface.tui import ApprovalDialog, LogStreamPanel, TUIDisplay

display = TUIDisplay()
panel = LogStreamPanel()
print(display.progress(3, 10))
panel.log("recon", "subdomain enumeration finished")
```

See the [API Reference](api-reference.md#terminal-ui) for constructor details.
