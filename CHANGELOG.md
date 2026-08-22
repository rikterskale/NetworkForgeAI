# Changelog

All notable changes to NetworkForgeAI are documented here. The project follows
the safety invariant that every offensive action requires explicit scope and,
for high-risk operations, human approval.

## [Unreleased]

### Offensive depth (vendor-grade)

- **Correlation & scoring pipeline** (`core/enrichment`): deduplicates findings,
  scores each with CVSS v3.1 and business-impact adjustment, suppresses obvious
  false positives, attaches advisory PoC steps, tags MITRE ATT&CK techniques,
  and correlates chained attack paths. Wired into a rebuilt `PlanningAgent`.
- **MITRE ATT&CK mapping** (`core/mitre`): finding-type and attack-stage → ATT&CK
  tactic/technique, plus a tactic coverage matrix for reports.
- **Web/API testing agents**: `WebApplicationAgent` drives `nikto`/`owasp-zap`
  for OWASP Top 10 surface (approval-gated); `APISecurityAgent` runs real
  `graphql-probe` and `jwt-analyzer` probes with advisory BOLA/BFLA reasoning.
- **Exploitation** (`NetworkExploitationAgent`): runs operator-supplied
  Metasploit modules one at a time; every run self-gates as CRITICAL and
  carries a justification. Confirmed sessions become `validated=True` findings.
- **Post-exploitation** (`PostExploitationAgent`): emits an ATT&CK-mapped plan
  with every objective blocked pending explicit approval; never self-executes.
- **Report depth** (`reporting/narrative`): `report.md` now includes an
  executive summary (severity table + top risks + CVSS), a MITRE ATT&CK
  coverage table, and correlated attack-chain narratives.
- **CLI**: new `--profile {recon,appsec,full}` selects agent depth, and
  `--exploit-plan <file.json>` supplies the operator's approved exploit plan.
- Approval requests can now carry caller-supplied context (`approval_details`)
  so an operator sees the exploit module and justification before authorizing.

## [0.1.0] - 2026-08-21

### Safety & Governance

- Human-in-the-loop approval gateway with fail-closed semantics, risk
  classification (LOW/MEDIUM/HIGH/CRITICAL), JSONL audit trail, and emergency
  stop.
- Scope enforcement engine supporting domains, wildcards, IPs, and CIDR
  ranges; every tool invocation fails closed without an explicit allow-list.

### Core

- Multi-agent orchestrator (`ScanOrchestrator`) with phases for
  reconnaissance, vulnerability scanning, attack path planning, exploitation,
  post-exploitation, and quality assurance on findings.
- Specialized agents including Planning (AGT-107) and Quality Assurance
  (AGT-108), both wired into the CLI scan pipeline.
- Shared knowledge base, message bus, task queue, persisted scan state, and
  state restoration.

### Tools

- Offensive toolkit integrations: nmap, masscan, nikto, OWASP ZAP, sqlmap,
  hydra, CrackMapExec, Impacket, Metasploit, browser automation, JWT analyzer,
  GraphQL probe.
- Cloud and directory audit wrappers (TLS-201..205): `cloud-aws` (ScoutSuite),
  `cloud-azure` (roadrecon), `cloud-gcp` (ScoutSuite), `kube-hunter`, and
  `ad-recon` (bloodhound-python); all approval-gated.

### Interfaces

- CLI with dry-run mode, tool inventory, report listing/reading restricted to
  the output directory, and configuration validation.
- Dependency-free dashboard HTTP API with operator/viewer RBAC.
- Terminal UI components (TUI-001..004): progress/table display, color-coded
  log streaming, interactive menus, and fail-closed approval dialogs.
- CLI approval prompts and live agent status display.

### Reporting

- JSON, CSV, SARIF, HTML, PDF, and Markdown report generation from a
  canonical, deduplicating finding model.
- Compliance mappings: OWASP Top 10 (2021), PTES, NIST CSF v1.1, ISO 27001,
  PCI-DSS.
- Validation engine with PoC advisory templates (never executed).

### Integrations

- Slack, Microsoft Teams, and Jira notifications over an HTTPS-only transport.
- Issue trackers: GitHub (INT-001), GitLab (INT-002), Linear (INT-005), and a
  generic webhook ticket client (INT-203).
- SMTP email report delivery (RPT-007 / INT-104) with mandatory STARTTLS for
  remote hosts.

### LLM Providers

- OpenAI, Anthropic, Google (via `google-genai`), LiteLLM, and Azure OpenAI
  adapters behind a common base interface; provider selection via env or
  `--provider`.

### Quality Gates

- Ruff lint/format, strict MyPy across the package, pytest with a 90% coverage
  floor (currently ~95%), Bandit + pip-audit security scans, documentation
  link audit, user-readiness gate, findings policy gate, and wheel smoke tests
  in CI. GitLab CI parity template included.
