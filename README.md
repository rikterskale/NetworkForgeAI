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
Host-side multi-agent reasoning with **human approval gateway**, one shared per-scan offensive sandbox, per-agent persistent model sessions, and disk-backed evidence consumed by interfaces.

### Component Map

| Component | Responsibility |
|-----------|----------------|
| CLI Entry | Argument parsing, Docker/model checks, scan bootstrap |
| Orchestrator | Sandbox creation, agent coordination, approval workflow enforcement |
| Agent Graph | Parent/child topology, statuses, mailboxes, approval states |
| Execution Engine | Streaming model loop, approval gate enforcement, lifecycle management |
| Agent Factory | System prompts, tools with approval wrappers, filesystem/shell capabilities |
| Model Adapter | OpenAI Agents SDK, LiteLLM compatibility, local LLM support |
| Context Control | Token estimation, history summarization, overflow recovery |
| Sandbox Manager | Containerized environment, Caido proxy, isolated toolkit |
| Approval Gateway | **Critical**: Human verification layer for all offensive actions |
| Terminal UI | Authenticated socket protocol with approval prompts |
| Web Dashboard | Live steering, approval queue, agent visualization |
| Reporting | Finding state, cost ledger, Markdown/JSON/CSV/SARIF output |

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
python -m pip install -e '.[runtime,dev]'
```

The virtual environment provides the `python` command consistently, even on
systems where only `python3` is available globally.

### 3. Run a scope-bound dry run
```bash
python3 -m networkforgeai.cli \
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
uvicorn networkforgeai.interface.dashboard:app --host 127.0.0.1 --port 8080
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

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Agent System](docs/agents.md)
- [Approval Workflow](docs/approval-system.md)
- [Reporting Guide](docs/reporting.md)
- [CI/CD Integration](docs/ci-cd.md)
- [Interface Guide](docs/interfaces.md)
- [Ethical Guidelines](docs/ethics.md)

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is provided for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any system. The developers assume no liability for misuse.
