# API Reference

Public Python surfaces for integrators and contributors. All offensive
capabilities remain behind the approval gateway regardless of API entry point.

## Reporting

### `networkforgeai.reporting`

```python
from networkforgeai.reporting import (
    Finding, Evidence, Severity, FindingStatus,
    to_json, to_csv, to_sarif, to_html,
    normalize_finding, deduplicate_findings, remediation_for,
)
```

- `Finding(type, target, ...)` — canonical finding record. `type` and `target`
  are required; severity/status accept strings and are normalized. `finding_id`
  is a stable hash of (type, target, title).
- `Evidence(kind, content, source, sensitive=False)` — sensitive evidence is
  redacted by default in every serialized output.
- `to_json / to_csv / to_sarif / to_html / to_pdf(findings)` — format generators; all
  normalize and deduplicate input first.
- `deduplicate_findings(values)` — collapses identical (type, target, title)
  records keeping the highest severity.

### `networkforgeai.reporting.compliance`

- `owasp_category(finding_type) -> str` — OWASP Top 10 (2021) category.
- `ptes_phase(finding_type) -> str` — PTES phase name.
- `nist_csf_category(finding_type) -> str` — NIST CSF v1.1 category.
- `annotate_compliance(findings)` — attaches the three mappings into each
  finding's metadata in place.
- `compliance_summary(raw_findings) -> dict` — per-framework coverage counts.

## Validation engine

### `networkforgeai.core.validation`

All outputs are advisory; nothing executes actions.

- `cvss_base_score(vector: str) -> float` — CVSS v3.1 base score.
- `cvss_for_severity(severity) -> float` — conservative baseline score.
- `generate_poc(finding, callback_host=...) -> PoCSuggestion` — advisory
  command templates; `requires_human_approval` is always `True`.
- `eliminate_false_positives(findings) -> list[ValidationVerdict]` —
  multi-signal status suggestions with confidence and reasons.
- `assess_impact(finding, asset_criticality="medium", internet_facing=False)`
  — business-context severity adjustment.

### `networkforgeai.core.validation_runner`

- `ExploitValidationRunner(sandbox, gateway, scope_policy)` — executes approved
  PoC command vectors inside the Docker sandbox only. Fails closed when the
  target is out of scope or approval is not granted.
- `validate_finding(finding, poc_commands) -> ValidationOutcome` — outcome
  includes per-command results and a suggested finding status.

## Safety core

### `networkforgeai.core.approval_gateway`

- `ApprovalGateway(mode, audit_log_path)` — modes: `manual`, `auto-low`
  (`moderate`), `auto-approved` (`lenient`). HIGH/CRITICAL risk always requires
  an explicit human decision.
- `request_approval(...) -> ApprovalRequest` then `wait_for_approval(id)`.
- `approve(id, approver_id)`, `reject(id, approver_id, reason)` — both audited
  to the JSONL audit log when configured.
- `emergency_stop(reason)` — cancels pending requests and blocks new ones until
  `reset_emergency_stop()`.

### `networkforgeai.core.scope`

- `ScopePolicy(allowed, excluded).contains(target) -> bool` — domain, wildcard,
  IP, and CIDR matching with exclusions taking precedence.

## Orchestration

### `networkforgeai.core.orchestrator`

- `ScanOrchestrator(ScanConfig(target, scope, excluded, approval_mode, save_dir))`
- `register_agent(agent)`, `start()`, `execute_scan()`.
- `pause()`, `resume()`, `stop()` — steering; `stop()` triggers gateway
  emergency stop.
- `ScanOrchestrator.from_state(scan_id, save_base_dir)` — restore persisted
  scans.

## Integrations

### `networkforgeai.integrations.notifications`

HTTPS-only JSON transport shared by both notifiers; HTTP endpoints raise
`ValueError`.

- `SlackNotifier(webhook_url).notify_findings(findings, scan_id=None) -> int`
- `JiraNotifier(base_url, email, api_token, project_key).create_issue_for_finding(finding) -> int`
- `TeamsNotifier(webhook_url).notify_findings(findings, scan_id=None) -> int`
- `summarize_findings(findings) -> dict` — sanitized severity summary.

### `networkforgeai.integrations.webhooks`

- `WebhookNotifier(endpoint, allow_http=False).send(event) -> int` — explicit
  webhook boundary for CI systems.

### `networkforgeai.integrations.trackers`

Issue-tracker clients (INT-001/002/005/203) sharing the HTTPS-only transport;
payloads carry sanitized summaries only and tokens are never logged.

- `finding_to_issue_fields(finding) -> dict` — sanitized title/body/severity triple.
- `select_notable_findings(findings, min_severity=None)` — filters normalized
  findings (default: critical and high).
- `GitHubIssueCreator(token, owner, repo, base_url=..., labels=[...])` — REST
  issue creation against `api.github.com`.
- `GitLabIssueCreator(token, project_id, base_url=..., labels=[...])` — REST
  issue creation against `gitlab.com` or a self-hosted instance.
- `LinearIssueCreator(api_key, team_id)` — GraphQL `issueCreate` mutation.
- `WebhookTicketClient(endpoint, headers=None)` — generic JSON ticket creation.

All constructors raise `ValueError` on empty tokens or non-HTTPS endpoints.

### `networkforgeai.integrations.siem`

SIEM forwarding and cross-source correlation (INT-201/202).

- `cef_encode(finding) -> str` — single-line CEF event with proper escaping.
- `SplunkHecForwarder(hec_url, token, index=None, source_type=...,
  use_cef=False)` — `forward_finding(finding)` / `forward_findings(findings)`
  post to a Splunk HTTP Event Collector over HTTPS.
- `correlate_findings(source_groups) -> list[dict]` — merges normalized
  findings from multiple scanner sources into records keyed by
  `(target, CWE|type)`; highest severity wins, sources are tracked per record.

### `networkforgeai.integrations.email_delivery`

SMTP report delivery (RPT-007 / INT-104).

- `EmailSettings(smtp_host, smtp_port=587, username=None, password=None,
  from_addr=..., to_addrs=[...], require_tls=True)`
- `SmtpReportSender(settings, smtp_factory=None).send_report(findings,
  scan_id=None, extra_body=None) -> EmailMessage`

STARTTLS is negotiated for every submission unless port 465 is used, which
switches to `SMTP_SSL`. Credentials are never included in message bodies.

## Cloud & directory tools

Wrappers in `networkforgeai.tools.cloud_tools`, all registered in the tool
inventory and all approval-gated (`requires_approval = True`). Scope
enforcement is inherited from `BaseTool`: execution fails closed without a
scope policy.

| Name | Class | Backing binary | Risk |
|------|-------|----------------|------|
| `cloud-aws` | `AwsAuditTool` | ScoutSuite (`--provider aws`) | MEDIUM |
| `cloud-azure` | `AzureAuditTool` | roadrecon | MEDIUM |
| `cloud-gcp` | `GcpAuditTool` | ScoutSuite (`--provider gcp`) | MEDIUM |
| `kube-hunter` | `KubernetesHuntTool` | kube-hunter | HIGH |
| `ad-recon` | `AdReconTool` | bloodhound-python | HIGH |

Example:

```python
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools import get_tool_by_name

tool = get_tool_by_name("kube-hunter", dry_run=True)
tool.scope_policy = ScopePolicy(["10.0.0.0/8"])
result = tool.execute("10.0.0.5", {"mode": "remote", "cis": True})
```

## Terminal UI

Components in `networkforgeai.interface.tui` — dependency-free ANSI surfaces
that fail closed in non-interactive sessions (TUI-001..004).

- `TUIDisplay(stream, colors)` — `progress(done, total, label)` bars and
  `table(headers, rows)` rendering.
- `LogStreamPanel(stream, colors)` — `log(source, message)` emits level-tagged,
  color-coded lines tagged ERROR/WARN/APPROVAL/INFO.
- `InteractiveMenu(title, items, ...)` — number-key navigation; returns `None`
  when non-interactive.
- `ApprovalDialog(gateway, stream, interactive)` — boxed HITL dialog usable as
  an approval-gateway callback; input errors reject the request.

## Dashboard HTTP API

See [Interface Guide](interfaces.md#dashboard-api) for the full endpoint list.
Authentication is `Authorization: Bearer <DASHBOARD_AUTH_TOKEN>` on every route
except `/health` and the operator console shell.
