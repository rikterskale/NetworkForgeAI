# Reporting

Each completed scan writes:

- `findings.json` for structured integration.
- `findings.csv` for spreadsheet workflows.
- `findings.sarif` for CI/security tooling.
- `report.md` for human review.
- `executive-summary.pdf` for management distribution.

An HTML rendering is also available through `networkforgeai.reporting.to_html`
for browser-based review; it escapes finding content and summarizes severity
counts.

Findings are sanitized before output to reduce accidental credential disclosure.
Reports are evidence containers, not proof that a vulnerability is exploitable; every
finding must retain its approval and validation context.

## Canonical finding model

Reports normalize dictionary findings into a validated `Finding` record with:

- stable identity derived from finding type, target, and title;
- normalized severity and lifecycle status;
- typed evidence records with sensitive content redacted by default;
- CVSS, CWE, OWASP, references, source, and metadata fields;
- baseline remediation guidance when a scanner does not provide remediation.

Duplicate findings collapse to one record, retaining the highest severity. Legacy
scanner fields such as PoCs, reproduction steps, timestamps, and agent identifiers
are preserved in metadata during normalization.

## Compliance mappings

`networkforgeai.reporting.compliance` maps finding types to standard
frameworks: OWASP Top 10 (2021), PTES phases, NIST CSF v1.1 categories,
ISO/IEC 27001:2022 Annex A controls, and PCI-DSS v4 requirements.
Use `annotate_compliance` to attach the mappings to normalized findings and
`compliance_summary` for per-framework coverage counts in reports.

## Validation engine

`networkforgeai.core.validation` provides advisory validation support:

- `cvss_base_score` computes CVSS v3.1 base scores from vector strings;
- `generate_poc` produces advisory, never-executed PoC suggestions that still
  require explicit human approval before any active use;
- `eliminate_false_positives` scores findings with multi-signal heuristics and
  suggests a lifecycle status;
- `assess_impact` adjusts severity using business context (asset criticality,
  internet exposure, finding class).

All outputs are advisory; nothing here bypasses the approval gateway.

## Notifications

`networkforgeai.integrations.notifications` delivers sanitized finding
summaries to collaboration tools over an HTTPS-only JSON transport:

- `SlackNotifier.notify_findings(...)` posts severity counts and the top
  findings to a Slack incoming webhook.
- `JiraNotifier.create_issue_for_finding(...)` opens one Jira issue per
  validated finding using basic-auth API tokens.

Payloads contain normalized, redacted finding data only; credentials are never
logged or embedded in reports.
