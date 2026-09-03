# NetworkForgeAI Capability Register & Roadmap

**Last Updated:** Phase 9 In Progress
**Status:** Validation engine, compliance mappings, HTML reports, and CLI approval/status UI delivered; strict MyPy gate extended
**Safety Model:** Explicit scope for every action; human approval for active and high-risk actions

Feature status is evidence-based. “Implemented” means the code path exists;
it does not by itself mean integration-tested, end-to-end-tested, or
production-hardened. See [docs/maturity.md](docs/maturity.md).

---

## 📊 Capability Status Legend

| Status | Meaning |
|--------|---------|
| ✅ **Implemented** | Fully functional, tested, and integrated |
| 🚧 **In Progress** | Currently being developed in active phase |
| 📋 **Planned** | Defined in architecture, scheduled for future phase |
| 🔍 **Research** | Requires investigation or proof-of-concept |
| ⚠️ **Blocked** | Dependent on external factor or decision |

---

## 🏗️ Phase 1: Foundation & Architecture (✅ COMPLETE)

### Core Infrastructure
| ID | Capability | Status | Notes |
|----|------------|--------|-------|
| INF-001 | Docker-based sandbox environment | ✅ | Multi-container setup with isolated network |
| INF-002 | Environment configuration management | ✅ | `.env.example` with all required variables |
| INF-003 | Python package structure | ✅ | Modular `networkforgeai` package |
| INF-004 | Dependency management | 🚧 | `pyproject.toml` is authoritative; lock/reproducibility work remains |
| INF-005 | Git repository initialization | ✅ | Ready for version control |

### Safety & Governance
| ID | Capability | Status | Notes |
|----|------------|--------|-------|
| SAF-001 | Human-in-the-Loop approval gateway | ✅ | `ApprovalGateway` class implemented |
| SAF-002 | Risk level classification system | ✅ | LOW/MEDIUM/HIGH/CRITICAL levels |
| SAF-003 | Approval requirement mapping | ✅ | Active and HIGH/CRITICAL actions use centralized approval policy |
| SAF-004 | Audit trail logging | ✅ | JSONL format with timestamps |
| SAF-005 | Scope enforcement engine | ✅ | Domain, wildcard, IP, CIDR, and exclusion matching |
| SAF-006 | Emergency stop mechanism | ✅ | Cancels pending approvals and blocks new actions |

---

## 🤖 Phase 2: Core Orchestrator & Agent System (✅ COMPLETE)

### Orchestration Engine
| ID | Capability | Status | Notes |
|----|------------|--------|-------|
| ORC-001 | Scan orchestrator core | ✅ | `ScanOrchestrator` class implemented |
| ORC-002 | Agent lifecycle management | ✅ | Start, stop, pause, resume controls |
| ORC-003 | Inter-agent communication bus | ✅ | Message queue with mailbox system |
| ORC-004 | Shared knowledge base | ✅ | `KnowledgeBase` class for findings |
| ORC-005 | Task distribution system | ✅ | Dynamic task assignment to agents |
| ORC-006 | Execution state persistence | ✅ | Save/load scan state to disk |
| ORC-007 | Concurrent agent coordination | ✅ | Thread-safe agent management |

### Agent Framework
| ID | Capability | Status | Notes |
|----|------------|--------|-------|
| AGT-001 | Base agent abstract class | ✅ | `BaseAgent` with standard interface |
| AGT-002 | Agent registration system | ✅ | Dynamic agent discovery |
| AGT-003 | Agent status tracking | ✅ | IDLE, WORKING, WAITING, STOPPED |
| AGT-004 | Tool access abstraction | ✅ | Unified tool interface for agents |
| AGT-005 | Context window management | ✅ | Adapter context preparation and bounded history |
| AGT-006 | Agent memory persistence | ✅ | Agent, knowledge-base, and task state persisted |

### Specialized Agents (Core Set)
| ID | Agent Type | Status | Capabilities |
|----|------------|--------|--------------|
| AGT-101 | Reconnaissance Agent | ✅ | Subdomain enum, port scanning, service detection |
| AGT-102 | Web Application Agent | ✅ | Drives `nikto`/`owasp-zap` for OWASP Top 10 surface (approval-gated); advisory hypotheses when no scanner; `--profile appsec`/`full` |
| AGT-103 | API Security Agent | ✅ | Real `graphql-probe` + `jwt-analyzer` probes; BOLA/BFLA reasoning advisory-only; `--profile appsec`/`full` |
| AGT-104 | Network Exploitation Agent | ✅ | Runs operator-supplied Metasploit modules one at a time; every run self-gates as CRITICAL with justification; `--profile full` + `--exploit-plan` |
| AGT-105 | Post-Exploitation Agent | ✅ | Emits an ATT&CK-mapped plan (persistence/privesc/cred-access/lateral/collection); every objective blocked pending approval; never self-executes |
| AGT-106 | Reporting Agent | ✅ | Finding compilation, report generation |
| AGT-107 | Planning Agent | ✅ | Attack path planning phase in `ScanOrchestrator` (approval-gated); registered in CLI scan |
| AGT-108 | Quality Assurance Agent | ✅ | Finding dedup/validation QA phase in `ScanOrchestrator`; registered in CLI scan |

---

## 🛠️ Phase 3: Offensive Toolkit Integration (🚧 PARTIAL)

**Completion Date:** Current Session  
**Implementation Summary:** Core framework with 8 production-ready tool integrations

### Network Testing Tools
| ID | Tool/Capability | Status | Integration Method |
|----|-----------------|--------|-------------------|
| TLS-001 | Nmap integration | ✅ | Python wrapper with XML parsing |
| TLS-002 | Masscan integration | ✅ | Python wrapper with JSON parsing |
| TLS-003 | Nikto web scanner | ✅ | Python wrapper with JSON/text parsing |
| TLS-004 | SQLmap integration | ✅ | Python wrapper (HITL required) |
| TLS-005 | Hydra credential testing | ✅ | Python wrapper (HITL required) |
| TLS-006 | Metasploit Framework | ✅ | `tools/metasploit_tool.py`: msfconsole resource scripts in the Docker sandbox; CRITICAL risk, always HITL; `check_only` mode |
| TLS-007 | CrackMapExec | ✅ | Python wrapper (HITL required) |
| TLS-008 | Impacket suite | ✅ | Multi-tool wrapper (HITL required) |

### Web Application Tools
| ID | Tool/Capability | Status | Integration Method |
|----|-----------------|--------|-------------------|
| TLS-101 | Caido proxy integration | ✅ | Docker container (already in compose) |
| TLS-102 | Burp Suite Community | ⚠️ | Blocked: REST API requires a Pro license; Community edition has no automation surface. Revisit if a Pro license is procured |
| TLS-103 | OWASP ZAP integration | ✅ | CLI wrapper with alert parsing |
| TLS-104 | Custom browser automation | ✅ | `tools/browser_tool.py`: headless Playwright surface discovery (optional `[browser]` extra; sandbox image needs Chromium) |
| TLS-105 | JWT tool integration | ✅ | `tools/jwt_tool.py`: passive decode + misconfiguration checks (alg=none, key-header/kid injection, expiry) |
| TLS-106 | GraphQL security tools | ✅ | `tools/graphql_tool.py`: introspection, IDE exposure, batching, and verbose-error probes (stdlib only) |

### Cloud & Infrastructure
| ID | Tool/Capability | Status | Target Platforms |
|----|-----------------|--------|------------------|
| TLS-201 | AWS testing tools | ✅ | `cloud-aws` tool (ScoutSuite wrapper), approval-gated |
| TLS-202 | Azure testing tools | ✅ | `cloud-azure` tool (ROADtools/roadrecon wrapper), approval-gated |
| TLS-203 | GCP testing tools | ✅ | `cloud-gcp` tool (ScoutSuite wrapper), approval-gated |
| TLS-204 | Kubernetes testing | ✅ | `kube-hunter` tool (HIGH risk, approval required) |
| TLS-205 | Active Directory tools | ✅ | `ad-recon` tool (bloodhound-python collector, HIGH risk) |

### Validation & Exploitation
| ID | Capability | Status | Notes |
|----|-----------|--------|-------|
| VAL-001 | PoC exploit generator | ✅ | Advisory templates via `core/validation.generate_poc` (never executed; HITL required) |
| VAL-002 | Exploit validation runner | ✅ | Sandbox-only execution behind approval gateway (`core/validation_runner.py`); fail-closed without approval/scope/sandbox |
| VAL-003 | False positive eliminator | ✅ | Multi-signal heuristics in `core/validation.eliminate_false_positives` |
| VAL-004 | CVSS calculator | ✅ | CVSS v3.1 base scores in `core/validation.cvss_base_score` |
| VAL-005 | Impact assessment engine | ✅ | Business-context severity adjustment in `core/validation.assess_impact` |

### Phase 3 Implementation Details

#### Core Framework Components
- **BaseTool**: Abstract base class with standardized interface
- **ToolResult**: Structured result dataclass with findings extraction
- **ToolRiskLevel**: LOW/MEDIUM/HIGH/CRITICAL classification
- **ToolCategory**: NETWORK_SCAN, WEB_SCAN, PASSWORD_ATTACK, etc.

#### Implemented Tools (12 Total)
1. **NmapTool** - Network scanning with service detection
2. **MasscanTool** - High-speed port scanning
3. **NiktoTool** - Web server vulnerability scanning
4. **OWASPZAPTool** - Web application security scanning
5. **SQLMapTool** - SQL injection testing (HIGH risk, HITL required)
6. **HydraTool** - Online password cracking (HIGH risk, HITL required)
7. **CrackMapExecTool** - Network exploitation (HIGH risk, HITL required)
8. **ImpacketTools** - SMB/LDAP protocol tools (HIGH risk, HITL required)
9. **MetasploitTool** - Exploitation console (CRITICAL risk, HITL required)
10. **BrowserAutomationTool** - Playwright surface discovery (optional `[browser]` extra)
11. **JwtAnalyzerTool** - JWT misconfiguration analysis (LOW risk, passive)
12. **GraphQLProbeTool** - GraphQL endpoint probing (MEDIUM risk)

#### Safety Features Implemented
- ✅ Target validation before execution
- ✅ Risk level classification for all tools
- ✅ Approval requirement flags (HIGH/CRITICAL)
- ✅ Dry-run mode for testing
- ✅ Sandbox mode support
- ✅ Timeout protection
- ✅ Audit trail logging

---

## 🧠 Phase 4: AI/LLM Integration (✅ ADAPTER LAYER COMPLETE)

**Completion Date:** Current Session  
**Implementation Summary:** Full LLM adapter layer with multi-provider support and prompt engineering library

### Model Adapters
| ID | Provider | Status | Capabilities |
|----|----------|--------|--------------|
| LLM-001 | OpenAI (GPT-4, o1) | ✅ | Full API support, tool calling, streaming |
| LLM-002 | Anthropic (Claude) | ✅ | Claude 3 family, tool use, vision |
| LLM-003 | Google (Gemini) | ✅ | Gemini Pro/Ultra/1.5, function calling |
| LLM-004 | LiteLLM unified interface | ✅ | Multi-provider routing |
| LLM-005 | Local LLM support | ✅ | Ollama, LM Studio, vLLM |
| LLM-006 | Azure OpenAI | ✅ | Enterprise deployment ready |
| LLM-007 | Model fallback logic | ✅ | Automatic retry on failure |
| LLM-008 | Google SDK migration (google-genai) | ✅ | `models/google_adapter.py` migrated from EOL `google-generativeai` to the `google-genai` SDK; `[llm]` extra and `requirements.txt` updated |

### AI Capabilities
| ID | Capability | Status | Notes |
|----|-----------|--------|-------|
| AIC-001 | Prompt engineering library | ✅ | Specialized prompts per agent type |
| AIC-002 | Tool selection reasoning | ✅ | Risk-aware tool selection |
| AIC-003 | Output parsing & validation | ✅ | JSON extraction, structured findings |
| AIC-004 | Chain-of-thought reasoning | ✅ | CoT templates for analysis/planning |
| AIC-005 | Multi-turn conversation mgmt | ✅ | History, truncation, summarization |
| AIC-006 | Token optimization | ✅ | Context control, estimation |
| AIC-007 | Response streaming | ✅ | Async streaming all providers |
| AIC-008 | Error recovery & retry | ✅ | Async bounded exponential backoff utility |

---

## 💻 Phase 5: User Interfaces (🚧 IN PROGRESS)

### Command Line Interface (CLI)
| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| CLI-001 | Main entry point | ✅ | `networkforgeai` command |
| CLI-002 | Scan initiation workflow | ✅ | Explicit target and scope setup |
| CLI-003 | Real-time status display | ✅ | Dependency-free live agent status via `interface/cli_ui.StatusDisplay` |
| CLI-004 | Approval prompt interface | ✅ | Terminal HITL prompts via `interface/cli_ui.ApprovalPrompt`; fail closed when non-interactive |
| CLI-005 | Results viewer | ✅ | Safe report listing and viewing |
| CLI-006 | Configuration manager | ✅ | Safety configuration validation |
| CLI-007 | Help & documentation | ✅ | Argparse help and interface guide |
| CLI-008 | Doctor / readiness diagnostics | ✅ | `--doctor` runs `networkforgeai.doctor.Doctor` with 4-state checks (passed/failed/skipped/unverified), remediation text on every failure, `--json` structured output, `--strict` promotes skipped/unverified to failure for CI gates; runs before Settings() load so a broken config is diagnosed rather than raising |
| CLI-009 | Auto-preflight before every real scan | ✅ | The doctor runs automatically before any scan (single-tool or orchestrated); a FAILED check aborts with exit 2 and prints remediations. `--dry-run` and the explicit `--preflight` command bypass it; `--skip-preflight` is the operator escape hatch for misreporting checks |
| CLI-010 | Diagnostic support bundle | ✅ | `--diagnose-bundle` writes `<output-dir>/diagnostic_bundle_<timestamp>.zip` containing `manifest.json`, `versions.json`, `config.json` (secret-safe), `doctor.json`, `tools.json`, and `audit_tail.jsonl` (last 200 lines). Excludes secrets and target evidence by default; runs even when Settings() cannot be instantiated (the bundle records the failure) |

### Web Dashboard
| ID | Feature | Status | Tech Stack |
|----|---------|--------|------------|
| GUI-001 | Web operator console | ✅ | Dependency-free single-file operator console at `GET /` (no React build chain) |
| GUI-002 | Live scan monitoring | ✅ | `/agents` + operator console polling |
| GUI-003 | Agent graph visualization | ✅ | Dependency-free SVG graph (scan node + per-agent status nodes) in the operator console |
| GUI-004 | Approval workflow UI | ✅ | Approval queue with approve/reject in console; audited via gateway |
| GUI-005 | Findings dashboard | ✅ | Scans tab: click a persisted scan to view its findings inline (severity-colored) |
| GUI-006 | Report generator | ✅ | Reports tab: browse and view generated reports in the console |
| GUI-007 | Historical runs browser | ✅ | Tabbed console GUI: Live / Scans & findings / Reports views |
| GUI-008 | Steering controls | ✅ | Pause/resume/emergency-stop via `/scan/*` endpoints; fail closed without live scan |
| GUI-009 | User authentication | ✅ | Bearer-token auth enforced fail-closed; optional read-only viewer token |
| GUI-010 | Role-based access control | ✅ | Operator vs viewer roles via `DASHBOARD_AUTH_TOKEN` / `DASHBOARD_VIEWER_TOKEN`; steering and approvals operator-only |

### Terminal UI (TUI)
| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| TUI-001 | Rich terminal display | ✅ | `interface/tui.TUIDisplay` — dependency-free ANSI progress bars and tables |
| TUI-002 | Live log streaming | ✅ | `interface/tui.LogStreamPanel` — level-tagged, color-coded lines |
| TUI-003 | Interactive menus | ✅ | `interface/tui.InteractiveMenu` — number-key navigation, fail-closed non-interactive |
| TUI-004 | Approval dialogs | ✅ | `interface/tui.ApprovalDialog` — boxed HITL dialog, fails closed |

---

## 📁 Phase 6: Data Management & Reporting (🚧 IN PROGRESS)

### Findings Management
| ID | Capability | Status | Notes |
|----|-----------|--------|-------|
| DAT-001 | Finding data model | ✅ | Canonical validated dataclass |
| DAT-002 | Evidence attachment | ✅ | Typed evidence with sensitive redaction |
| DAT-003 | Deduplication logic | ✅ | Stable type/target/title identity |
| DAT-004 | Severity normalization | ✅ | Informational/low/medium/high/critical mapping |
| DAT-005 | Remediation templates | ✅ | Baseline guidance for core finding types |

### Report Generation
| ID | Format | Status | Use Case |
|----|--------|--------|----------|
| RPT-001 | Markdown | ✅ | Developer-friendly reports |
| RPT-002 | JSON | ✅ | Machine consumption, APIs |
| RPT-003 | CSV | ✅ | Spreadsheet analysis |
| RPT-004 | SARIF | ✅ | IDE integration, CI/CD |
| RPT-005 | PDF | ✅ | Dependency-free executive-summary PDF via `reporting.generators.to_pdf`; written per scan as `executive-summary.pdf` |
| RPT-006 | HTML | ✅ | Escaped, severity-styled HTML via `reporting.generators.to_html` |
| RPT-007 | Email delivery | ✅ | `integrations/email_delivery.SmtpReportSender` — STARTTLS/SSL SMTP delivery of sanitized summaries |

### Compliance & Standards
| ID | Standard | Status | Notes |
|----|----------|--------|-------|
| CMP-001 | OWASP Top 10 mapping | ✅ | `reporting/compliance.py` (2021 categories) |
| CMP-002 | PTES alignment | ✅ | Phase mapping in `reporting/compliance.py` |
| CMP-003 | NIST CSF mapping | ✅ | CSF v1.1 categories in `reporting/compliance.py` |
| CMP-004 | ISO 27001 controls | ✅ | ISO/IEC 27001:2022 Annex A mapping in `reporting/compliance.py` |
| CMP-005 | PCI-DSS requirements | ✅ | PCI-DSS v4 requirement mapping in `reporting/compliance.py` |

---

## 🔌 Phase 7: Integrations & CI/CD (🚧 IN PROGRESS)

### Version Control & Issue Tracking
| ID | Platform | Status | Integration Type |
|----|----------|--------|------------------|
| INT-001 | GitHub | ✅ | Issues via REST (`GitHubIssueCreator`); Actions gate already in CI |
| INT-002 | GitLab | ✅ | Issues via REST (`GitLabIssueCreator`); CI parity template shipped |
| INT-003 | Bitbucket | ✅ | Issues via REST (`BitbucketIssueCreator`); Pipelines can run the CI parity templates |
| INT-004 | Jira | ✅ | Issue creation from findings via REST (`integrations/notifications.py`, HTTPS-only) |
| INT-005 | Linear | ✅ | Issue creation via GraphQL (`LinearIssueCreator`) |
| INT-006 | Azure DevOps | ✅ | Work items via REST JSON-Patch (`AzureDevOpsWorkItemCreator`); Azure Pipelines parity template shipped |

### Communication & Collaboration
| ID | Platform | Status | Integration Type |
|----|----------|--------|------------------|
| INT-101 | Slack | ✅ | Finding summaries to incoming webhooks (`integrations/notifications.py`, HTTPS-only) |
| INT-102 | Microsoft Teams | ✅ | Message-card summaries to incoming webhooks (`integrations/notifications.py`, HTTPS-only) |
| INT-103 | Discord | ✅ | Webhook notifications (`DiscordNotifier`) sharing the HTTPS-only transport |
| INT-104 | Email (SMTP) | ✅ | Same transport as RPT-007; TLS enforced for remote hosts |

### CI/CD Platforms
| ID | Platform | Status | Capabilities |
|----|----------|--------|--------------|
| CICD-001 | GitHub Actions | ✅ | Findings policy gate and readiness artifacts |
| CICD-002 | GitLab CI | ✅ | Parity template `templates/gitlab-ci-networkforgeai.yml` (lint/test/typecheck/security/docs/findings gate) |
| CICD-003 | Jenkins | ✅ | Declarative pipeline parity template `templates/Jenkinsfile` |
| CICD-004 | CircleCI | ✅ | Config parity template `templates/circleci-config.yml` (orb not required) |
| CICD-005 | Azure Pipelines | ✅ | Parity template `templates/azure-pipelines.yml` |

### Security Tools
| ID | Tool Category | Status | Integration Purpose |
|----|---------------|--------|---------------------|
| INT-201 | SIEM systems | ✅ | Splunk HEC forwarder with JSON and CEF event modes (`integrations/siem.SplunkHecForwarder`); HTTPS-only |
| INT-202 | Vulnerability scanners | ✅ | Cross-source finding correlation by target + CWE/type (`integrations/siem.correlate_findings`) |
| INT-203 | Ticketing systems | ✅ | Generic HTTPS JSON webhook ticket creation (`WebhookTicketClient`) |
| INT-204 | Secret managers | ✅ | `integrations/secrets.SecretResolver`: env/file/Vault-style HTTPS refs; inline secrets rejected, values never logged |

---

## 🧪 Phase 8: Testing & Quality Assurance (✅ CORE GATES COMPLETE)

### Test Coverage
| ID | Area | Status | Notes |
|----|------|--------|-------|
| TST-001 | Unit tests | ✅ | Pytest framework and regression coverage |
| TST-002 | Integration tests | ✅ | Reporting, webhook, and workflow tests |
| TST-003 | Agent behavior tests | ✅ | Mock approvals and model-independent paths |
| TST-004 | Safety mechanism tests | ✅ | Approval bypass prevention and fail-closed checks |
| TST-005 | Performance tests | ✅ | CPU-only budget tests for hot paths (`tests/test_performance.py`) — summarize, report generation, normalization, concurrent approvals |
| TST-006 | Security tests | ✅ | Adversarial suite `tests/test_safety_adversarial.py`: scope evasion, approval fail-closed, RBAC, path confinement |

### Quality Gates
| ID | Gate | Status | Criteria |
|----|------|--------|----------|
| QA-001 | Code linting | ✅ | Ruff checks and format verification in CI |
| QA-002 | Type checking | ✅ | Strict MyPy gate for maintained typed core surfaces; legacy modules tracked for follow-up |
| QA-003 | Documentation coverage | ✅ | Documentation audit in CI |
| QA-004 | Test coverage threshold | ✅ | >90% line coverage |
| QA-005 | Security scan | ✅ | Bandit and pip-audit in CI; Semgrep remains future work |

### Type-checking follow-up backlog

The maintained typed surfaces pass strict MyPy in CI. **As of the current
session, `mypy --strict networkforgeai` passes for the entire package** and the
CI gate runs strict MyPy over all 44 modules; LLM SDK extras (`.[llm]`) are now
installed in CI so optional provider adapters typecheck against real stubs.

| Priority | Area | Scope | Exit criterion |
|----------|------|-------|----------------|
| 1 | Core orchestration | `networkforgeai/core/orchestrator.py` and agent lifecycle types | ✅ Strict MyPy passes |
| 2 | LLM adapters | Anthropic, Google, and OpenAI adapter implementations | ✅ Optional-provider imports typed against installed SDKs |
| 3 | Dashboard / CLI UI / validation / compliance | `interface/dashboard.py`, `interface/cli_ui.py`, `core/validation.py`, `reporting/compliance.py` | ✅ Pass strict MyPy |
| 4 | Repository gate | Full package | ✅ `make typecheck` runs `mypy --strict networkforgeai` and passes |

---

## 📚 Phase 9: Documentation & Training (🚧 IN PROGRESS)

### User Documentation
| ID | Document | Status | Audience |
|----|----------|--------|----------|
| DOC-001 | README quickstart | ✅ | All users |
| DOC-002 | Installation guide | ✅ | `docs/installation.md` (incl. contributor `[llm]` extra) |
| DOC-003 | Configuration reference | ✅ | `docs/configuration.md` |
| DOC-004 | CLI command reference | ✅ | `docs/cli-reference.md` (verified against current CLI flags) |
| DOC-005 | GUI user manual | ✅ | `docs/gui-user-manual.md` — tabs, auth, safety model; linked from README and interface guide |
| DOC-006 | Agent playbook | ✅ | `docs/agents.md` |
| DOC-007 | Troubleshooting guide | ✅ | `docs/troubleshooting.md` |
| DOC-008 | FAQ | ✅ | `docs/faq.md` |

### Phase 9 Initial Deliverables

- [x] Publish installation and configuration guides.
- [x] Document CLI workflows and approval behavior.
- [x] Add architecture, API, security-model, and deployment references. (all ✅; deployment covered in `docs/deployment.md`)
- [x] Create example scan scenarios and operator training material. (`docs/scenarios.md`)

### Technical Documentation
| ID | Document | Status | Audience |
|----|----------|--------|----------|
| DOC-101 | Architecture overview | ✅ | `docs/architecture.md` (packages, execution flow, safety model, persistence) |
| DOC-102 | API reference | ✅ | `docs/api-reference.md` (reporting, validation, safety core, orchestration, integrations) |
| DOC-103 | Contributing guide | ✅ | `CONTRIBUTING.md` (safety invariants, quality gates, conventions) |
| DOC-104 | Security model whitepaper | ✅ | `SECURITY.md`, `docs/ethics.md`, `docs/approval-system.md` |
| DOC-105 | Deployment guide | ✅ | `docs/deployment.md` (production shapes, hardening, storage, upgrade/rollback) |

### Training Materials
| ID | Material | Status | Format |
|----|----------|--------|--------|
| TRN-001 | Video tutorials | 🔍 | YouTube/Loom |
| TRN-002 | Interactive labs | 🔍 | Docker-based scenarios |
| TRN-003 | Certification program | 🔍 | Future consideration |
| TRN-004 | Example scan scenarios | ✅ | `docs/scenarios.md` (six guided, safety-first exercises) |

---

## 🚀 Phase 10: Advanced Features (🔍 RESEARCH)

### AI Enhancements
| ID | Feature | Status | Complexity |
|----|---------|--------|------------|
| ADV-001 | Multi-agent debate | 🚧 FOUNDATION | Bounded independent opinions and one critique round; advisory output only |
| ADV-002 | Self-improvement loop | 🔍 | Very High |
| ADV-003 | Transfer learning | 🔍 | High |
| ADV-004 | Few-shot learning examples | 🚧 FOUNDATION | Bounded, opt-in trusted examples are formatted into agent analysis context |
| ADV-005 | Retrieval-augmented generation | 🚧 HYBRID FOUNDATION | Agent context uses local retrieval; optional caller-supplied vectors now add semantic ranking |

### Automation & Intelligence
| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| ADV-101 | Attack path auto-discovery | ✅ | `core/attack_paths.discover_attack_paths`: stage-chained attack graph with scored simple paths (advisory only) |
| ADV-201 | MITRE ATT&CK technique mapping | ✅ | `core/mitre`: finding-type/stage → ATT&CK tactic+technique, plus tactic coverage matrix |
| ADV-202 | Finding enrichment & correlation pipeline | ✅ | `core/enrichment.enrich_findings`: dedup + CVSS + impact + FP suppression + ATT&CK + attack paths; wired into `PlanningAgent` |
| RPT-201 | Vendor-grade report narrative | ✅ | `reporting/narrative`: executive summary, ATT&CK coverage table, and attack-chain narratives in `report.md` |
| ADV-102 | Vulnerability correlation | 🔍 | ML-based pattern matching |
| ADV-103 | Threat intelligence integration | 🔍 | External feeds |
| ADV-104 | Predictive risk scoring | 🔍 | Historical data analysis |
| ADV-105 | Automated remediation validation | ✅ | Approval-gated re-test planner `core/revalidation.build_retest_plan` mapping findings to inventory tools |

### Enterprise Features
| ID | Feature | Status | Target |
|----|---------|--------|--------|
| ENT-001 | Multi-tenant support | 🔍 | MSPs, consultants |
| ENT-002 | SSO/SAML integration | 🔍 | Enterprise auth |
| ENT-003 | Audit compliance exports | 🔍 | Regulatory needs |
| ENT-004 | Custom branding | 🔍 | White-label option |
| ENT-005 | HA/DR deployment | 🔍 | Production resilience |

---

## 📈 Roadmap Timeline

### Immediate (Next 2 Weeks - Phases 3-4)
- [x] Complete offensive toolkit integration (Phase 3) ✅ **DONE**
- [ ] Implement LLM adapters and AI capabilities (Phase 4)
- [x] Add 3-5 core tools with full HITL workflow ✅ **DONE (8 tools)**

### Short-term (Month 1 - Phases 5-6)
- [ ] Build CLI with full guided workflows
- [ ] Deploy web dashboard MVP
- [ ] Implement all report formats
- [ ] Add evidence collection and PoC generation

### Mid-term (Months 2-3 - Phases 7-8)
- [ ] CI/CD integrations (GitHub Actions, GitLab CI)
- [ ] Issue tracker integrations (Jira, Linear)
- [ ] Comprehensive test suite
- [ ] Performance optimization

### Long-term (Months 4-6 - Phases 9-10)
- [ ] Complete documentation suite
- [ ] Training materials and example scenarios
- [ ] Advanced AI features (RAG, multi-agent debate)
- [ ] Enterprise features (SSO, multi-tenant)

---

## 🎯 Next Priority Items

Based on current progress (Phase 9 documentation complete; Phases 5–7 partially
delivered), the following capabilities are highest priority:

1. **LLM-008**: Migrate the Google adapter from the EOL `google-generativeai` SDK to `google-genai` (Phase 4)
4. **RPT-007 / INT-104**: Email delivery of reports and alerts over SMTP with TLS (Phases 6–7)

Previously listed items (LLM adapters, CLI, dashboard MVP, validation engine,
dashboard RBAC, agent graph, Metasploit, PDF reports, browser automation,
GitLab CI parity, Teams notifications, JWT/GraphQL tools, ISO/PCI mappings) are
complete and tracked in their phase tables above.

---

## 📝 Change Log

| Date | Phase | Changes |
|------|-------|---------|
| Current Session | Phase 6/7 (cont.) | ✅ CMP-004/005: ISO/IEC 27001:2022 Annex A and PCI-DSS v4 mappings in `reporting/compliance.py` (annotated + summarized like OWASP/NIST) |
| Current Session | Phase 3 (cont.) | ✅ TLS-105/106: JWT analyzer (`jwt-analyzer`) and GraphQL probe (`graphql-probe`) tools — 12 tools total |
| Current Session | Phase 7 (cont.) | ✅ INT-102 Microsoft Teams message-card notifications via shared HTTPS-only transport |
| Current Session | Phase 6/7 (cont.) | ✅ RPT-005 dependency-free executive-summary PDF (`to_pdf`, per-scan `executive-summary.pdf`); CICD-002 GitLab CI parity template (`templates/gitlab-ci-networkforgeai.yml`) |
| Current Session | Phase 3 (cont.) | ✅ TLS-104 browser automation: `tools/browser_tool.py` — headless Playwright surface discovery behind the optional `[browser]` extra |
| Current Session | Phase 3 (cont.) | ✅ TLS-006 Metasploit integration: msfconsole resource scripts executed only in the Docker sandbox, CRITICAL risk with mandatory HITL approval and `check_only` mode |
| Current Session | Phase 5 (cont.) | ✅ GUI-003 agent graph visualization: dependency-free SVG scan/agent topology in the operator console |
| Current Session | Phase 5 (cont.) | ✅ GUI-009/GUI-010: dashboard RBAC — optional `DASHBOARD_VIEWER_TOKEN` grants read-only access to reports/scans/agents; approvals and steering remain operator-only |
| Current Session | Phase 9 (cont.) | ✅ DOC-105 deployment guide (`docs/deployment.md`) and TRN-004 example scan scenarios (`docs/scenarios.md`); "Next Priority Items" refreshed |
| Current Session | Phase 5 (cont.) | ✅ Dashboard API: approval queue, steering controls, agent status, per-scan findings endpoints; dependency-free operator console at `GET /` (GUI-001/002/004/005/006/007/008) |
| Current Session | Phase 9 (cont.) | ✅ Documentation audit: historical PHASE*.md snapshots archived to `docs/history/`; DOC-002/003/004/006/007 verified against code and marked complete; installation guide updated with `[llm]` contributor extra |
| Current Session | Phase 7 (cont.) | ✅ INT-004 Jira issue creation and INT-101 Slack finding summaries via shared HTTPS-only JSON transport (`integrations/notifications.py`) |
| Current Session | Phase 3 (cont.) | ✅ VAL-002 exploit validation runner: approved PoC commands execute only inside the Docker sandbox, fail closed on missing approval/scope/sandbox |
| Current Session | Phase 8 (cont.) | ✅ Full-repository strict MyPy: `make typecheck` now runs `mypy --strict networkforgeai` (44 modules); CI installs `.[llm]` extras for adapter stubs |
| Current Session | Phase 9 (cont.) | ✅ Validation engine (VAL-001/003/004/005), compliance mappings (CMP-001..003), HTML reports (RPT-006), CLI approval prompts + status display (CLI-003/004); strict MyPy gate extended to dashboard, CLI UI, validation, and compliance modules |
| Current Session | Phase 9 | ✅ Phase 8 core quality gates closed; strict MyPy gate added for maintained typed surfaces; Phase 9 documentation work started |
| Current Session | Phase 3 | ✅ COMPLETE: Implemented BaseTool framework, 8 tool integrations (Nmap, Masscan, Nikto, OWASP ZAP, SQLMap, Hydra, CrackMapExec, Impacket) |
| 2025-01-XX | Phase 1 | Foundation architecture, safety systems, repo structure |
| 2025-01-XX | Phase 2 | Orchestrator, agent framework, 6 specialized agents |
| TBD | Phase 3 | Toolkit integration |
| TBD | Phase 4 | AI/LLM integration |
| TBD | Phase 5 | User interfaces |
| TBD | Phase 6 | Reporting |
| TBD | Phase 7 | Integrations |
| TBD | Phase 8 | Testing |
| TBD | Phase 9 | Documentation |
| TBD | Phase 10 | Advanced features |

---

## 🔐 Safety Reminders

- **ALL exploitation actions require explicit human approval** before execution
- **Scope enforcement** must be validated before every scan
- **Audit trails** are immutable and must be preserved
- **Emergency stop** capability must always be accessible
- **No autonomous exploitation** - AI assists, humans decide

---

*This document should be updated at the end of each development phase.*
