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
- `summarize_findings(findings) -> dict` — sanitized severity summary.

### `networkforgeai.integrations.webhooks`

- `WebhookNotifier(endpoint, allow_http=False).send(event) -> int` — explicit
  webhook boundary for CI systems.

## Dashboard HTTP API

See [Interface Guide](interfaces.md#dashboard-api) for the full endpoint list.
Authentication is `Authorization: Bearer <DASHBOARD_AUTH_TOKEN>` on every route
except `/health` and the operator console shell.
