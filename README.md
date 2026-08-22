# NetworkForgeAI

**Authorized AI-Assisted Penetration Testing Framework with Human-in-the-Loop Control**

NetworkForgeAI is a security validation platform that combines AI-assisted analysis with mandatory human approval gates for all offensive operations. Designed for authorized red teams, penetration testers, and cyber-range operators.

## ⚠️ Ethical Usage Notice

This tool is **strictly** for:
- Authorized internal red team operations
- Certified consulting engagements with written authorization
- Cyber-range training environments
- Legitimate security validation on owned/approved assets

**All exploitation actions require explicit human approval before execution.** No autonomous exploit deployment is permitted.

## Overview

NetworkForgeAI provides AI-assisted security testing with:
- Multi-agent collaboration for recon, analysis, and planning
- **Mandatory human approval** for all exploitation attempts
- Real-time dashboard with live steering capabilities
- Validated findings with reproduction steps (not automated exploit delivery)
- Comprehensive reporting for compliance and remediation

## Key Capabilities

### Human-in-the-Loop Security Testing
- AI suggests attack paths, humans approve each step
- Explicit confirmation required before any exploitation
- Granular approval controls (per-action, per-target, per-severity)
- Audit trail of all approvals and decisions

### Multi-Agent Orchestration
- Specialized AI agents for reconnaissance, vulnerability analysis, and attack path planning
- Agents collaborate and share discoveries
- Parallel execution across approved targets
- Dynamic coordination with human oversight

### Developer-First Interfaces
- **CLI**: Guided workflows with approval prompts
- **GUI**: Visual approval interface with real-time agent status
- **Live Dashboard**: Run status, agent graph, steering controls, approval queue

### Reporting
- Compliance-ready penetration test reports
- Findings in Markdown, JSON, CSV, and SARIF formats
- Complete reproduction steps for validated vulnerabilities
- Email delivery and sharing capabilities

### Application Security Testing
- AI-assisted detection of OWASP Top 10 vulnerabilities
- Business logic flaw identification
- SAST + DAST capabilities (human-validated results)

### CI/CD Integration
- Security gates in pipelines (GitHub, GitLab, Bitbucket)
- Integration with Jira, Linear, Slack for finding tracking
- Block deployments based on severity thresholds

## Prerequisites

- Docker (running)
- LLM API key (OpenAI, Anthropic, Google, or local LLM)
- Written authorization for all target systems
- Python 3.10+

## Architecture

### Central Pattern
Host-side multi-agent coordination behind a **human approval gateway**. Agents
drive real tool wrappers (e.g. `nmap`, `sqlmap`) through the gateway and, when a
model is configured, use it for advisory triage. Evidence is written to disk and
consumed by the CLI, TUI, and dashboard. Agents never fabricate findings: when a
required tool or model is unavailable they record an explicit status and return
no results.

### Component Map

| Component | Responsibility |
|-----------|----------------|
| CLI Entry | Argument parsing, scope validation, scan bootstrap, tool registry wiring |
| Orchestrator | Agent coordination, phase execution, approval workflow enforcement, state persistence |
| Agents | Recon / vulnerability / planning / QA agents with mailboxes and approval states |
| Tool Wrappers | Command builders + output parsers with scope checks and approval gating (`execute_async`) |
| Model Adapters | Pluggable OpenAI / Anthropic / Google (google-genai) / local / LiteLLM chat adapters (optional) |
| Context Control | Token estimation and context truncation (`prepare_context`), retry with backoff |
| Sandbox Runner | Optional Docker-isolated command execution, fail-closed when unavailable |
| Approval Gateway | **Critical**: human verification layer for all high-risk actions, with audit log |
| Terminal UI | Approval prompts and status display for CLI operation |
| Web Dashboard | Read-only report/scan/agent surfaces; live steering + approval queue when a scan is attached |
| Reporting | Finding aggregation and Markdown/JSON/CSV/SARIF/PDF output |

> Note: LLM adapters are optional. Without a configured provider the framework
> runs deterministically — recon and validation are driven entirely by the tool
> wrappers, and vulnerability hypotheses (which require a model) are simply not
> produced. See [Agent System](docs/agents.md) for the honest-output contract.

## Quick Start

### 1. Clone and Configure
```bash
git clone <repository-url>
cd networkforgeai
cp .env.example .env
# Edit .env with your LLM API key and authorized targets
```

### 2. Install the package
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install '.[runtime]'
```

The virtual environment provides the `python` command consistently, even on
systems where only `python3` is available globally.

Install `.[runtime,dev]` only when you plan to contribute code or run the full
developer test suite. After installation, the `networkforgeai` command is
available directly from the virtual environment.

### 3. Run a scope-bound dry run
```bash
networkforgeai \
  --target example.com \
  --scope example.com \
  --tool nmap \
  --dry-run
```

Every invocation requires an explicit allow-list scope. High-risk tools also
require an approval gateway and cannot execute directly without one.

### 4. Start the dashboard API (optional)
```bash
export DASHBOARD_AUTH_TOKEN='replace-with-a-random-token'
export REPORT_OUTPUT_DIR=./reports
python -m uvicorn networkforgeai.interface.dashboard:app --host 127.0.0.1 --port 8080
```
The dashboard currently exposes authenticated read-only health and report-listing endpoints.

### 5. Run the production readiness gate locally

```bash
make ci
```

The gate checks formatting, linting, tests and coverage, dependency/security scans,
documentation links, Docker configuration, safe defaults, approval fail-closed
behavior, and report generation. It never scans an external target.

## Workflows

### Reconnaissance Workflow
1. AI agents perform passive/active recon on authorized targets
2. Findings presented for human review
3. Approved findings move to vulnerability analysis phase

### Vulnerability Analysis Workflow
1. AI analyzes potential vulnerabilities from recon data
2. Hypotheses generated with confidence scores
3. Human approves which hypotheses to validate
4. Validation tests run in sandbox (non-destructive)
5. Results require human confirmation before reporting

### Attack Path Planning Workflow
1. AI constructs potential attack chains from validated vulnerabilities
2. Attack paths displayed with risk assessment
3. Human selects which paths to explore (if authorized)
4. **Each exploitation step requires explicit approval**
5. Proof-of-concept commands provided for manual verification

## Approval System

### Approval Levels
- **Recon Actions**: Auto-approved within scope boundaries
- **Vulnerability Validation**: Requires confirmation before active testing
- **Exploitation Attempts**: **Always requires explicit human approval**
- **Post-Exploitation**: **Always requires explicit human approval with justification**

### Approval Interface
- CLI: Interactive prompts with detailed context
- GUI: Visual approval queue with one-click approve/reject
- API: Programmatic approval for automation with audit logging

## Reporting Formats

- **Markdown**: Human-readable reports with executive summary
- **JSON**: Machine-readable findings for integration
- **CSV**: Spreadsheet-compatible data export
- **SARIF**: Static Analysis Results Interchange Format for IDE integration

## CI/CD Integration

Example GitHub Actions workflow:
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  networkforge-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run NetworkForgeAI Scan
        run: |
          docker-compose run networkforgeai \
            --target ${{ github.event.repository.url }} \
            --mode sast-dast \
            --ci-mode
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/latest.sarif
```

## Documentation

- [Changelog](CHANGELOG.md)
- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [CLI Reference and Beginner Workflows](docs/cli-reference.md)
- [Troubleshooting Guide](docs/troubleshooting.md)
- [Example Scan Scenarios](docs/scenarios.md)
- [Deployment Guide](docs/deployment.md)
- [Agent System](docs/agents.md)
- [GUI User Manual](docs/gui-user-manual.md)
- [Approval Workflow](docs/approval-system.md)
- [Reporting Guide](docs/reporting.md)
- [CI/CD Integration](docs/ci-cd.md)
- [Advanced Features](docs/advanced-features.md)
- [Interface Guide](docs/interfaces.md)
- [API Reference](docs/api-reference.md)
- [Architecture Overview](docs/architecture.md)
- [FAQ](docs/faq.md)
- [Ethical Guidelines](docs/ethics.md)
- [Contributing](CONTRIBUTING.md)

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any system. The developers assume no liability for misuse.
