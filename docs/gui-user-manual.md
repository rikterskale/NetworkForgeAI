# GUI User Manual

The NetworkForgeAI operator console is a dependency-free web GUI served by the
dashboard. It requires no build step and no external assets; everything runs
from the single page the dashboard serves.

## Starting the dashboard

```bash
export DASHBOARD_AUTH_TOKEN="<operator token>"   # required, never use "changeme"
export REPORT_OUTPUT_DIR=./reports               # optional, default ./reports
uvicorn networkforgeai.interface.dashboard:app --host 127.0.0.1 --port 8443
```

Optionally set `DASHBOARD_VIEWER_TOKEN` for a second, read-only role. Open
`http://127.0.0.1:8443/` in a browser.

## Signing in

- Paste your bearer token into the **Bearer token** field on any tab and press
  **Connect / Refresh**.
- The token is kept in browser memory only — it is never stored, logged, or
  baked into the page. Re-enter it after a page reload.
- Operator tokens can approve requests and steer scans. Viewer tokens can only
  read reports, scans, and findings; mutating calls are rejected with `401`.

## Tabs

### Live

The operational view for an active scan:

- **Scan steering** — Pause, Resume, and Stop (emergency stop). Stopping
  cancels all pending approvals and blocks new ones until restart.
- **Agent graph** — radial view of the scan and its agents; node color encodes
  agent status (green working, amber waiting/approval, grey idle, red stopped).
- **Agent status** — table of agent ID, name, status, and capabilities.
- **Approval queue** — pending high-risk actions with Approve / Reject buttons.
  Every decision is written to the gateway's audit trail. If an emergency stop
  is active the queue shows a red banner and new requests are blocked.

If no live scan is attached to the dashboard these views fail closed with
connection errors rather than showing stale data.

### Scans & findings

- Lists persisted scans from the configured output directory: scan ID,
  status, target, and finding count.
- Click a row to load that scan's findings inline: type, title, severity
  (color-coded), target, status, and remediation guidance.
- Findings are read-only; remediation happens outside the console.

### Reports

- Lists generated report files under the report directory (JSON, SARIF, CSV,
  HTML, PDF, Markdown).
- Click a file to view it in the pane below. JSON reports are pretty-printed;
  binary formats (PDF) should be downloaded from disk instead.
- Path traversal is blocked server-side: only files inside the report
  directory are reachable.

## Safety model

The GUI never starts scans and never bypasses controls:

- All offensive actions still require explicit scope allow-listing at the tool
  boundary.
- High-risk actions require human approval regardless of which interface is
  used; the approval queue is just one window onto the shared gateway.
- Viewer tokens cannot mutate anything; unauthenticated requests receive `401`
  and operator endpoints without a live scan return `503`.

See [Approval Workflow](approval-system.md) for the underlying gateway
semantics and [Interface Guide](interfaces.md#dashboard-api) for the raw HTTP
API behind each view.
