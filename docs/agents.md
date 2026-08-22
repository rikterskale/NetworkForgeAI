# Agents

Agents inherit from `BaseAgent` and receive an approval gateway, message bus,
knowledge base context, optional model adapter, and a registry of tool wrappers.

The core agents are:

- `ReconAgent` — resolves hosts via DNS (stdlib) and runs approved port scans
  through the registered `nmap`/`masscan` wrappers, converting real scan output
  into findings.
- `VulnerabilityScannerAgent` — validates SQL injection via the `sqlmap` wrapper
  (which self-gates HIGH-risk approval) and, when no active-testing tool is
  available, emits advisory hypotheses if a model is configured.
- `PlanningAgent` — runs the correlation/enrichment engine
  (`core.enrichment`): normalizes and deduplicates findings, scores each with
  CVSS v3.1 and business-impact adjustment, suppresses obvious false positives,
  tags MITRE ATT&CK techniques, and correlates chained attack paths across
  hosts. Publishes `enriched_findings`, `attack_paths`, and `attack_coverage`
  to shared context.
- `WebApplicationAgent` — drives the registered `nikto`/`owasp-zap` wrappers
  against discovered URLs for OWASP Top 10 surface. Active scans are approval-
  gated at the agent boundary; when no scanner is registered it emits advisory
  hypotheses (if a model is configured) or an honest `*_status` note.
- `APISecurityAgent` — probes GraphQL endpoints (`graphql-probe`) and analyses
  captured JWTs (`jwt-analyzer`) from real tool output, and reasons about
  BOLA/BFLA access-control weaknesses as advisory hypotheses only.
- `NetworkExploitationAgent` — executes real exploits **only** from an explicit
  operator-supplied `exploit_plan`, one Metasploit module at a time. The
  Metasploit wrapper self-gates as CRITICAL, so no module runs without an
  explicit human approval carrying justification. Confirmed sessions become
  `validated=True` findings; rejections and misses are recorded as status, never
  fabricated.
- `PostExploitationAgent` — produces an ATT&CK-mapped post-exploitation plan
  (persistence, privilege escalation, credential access, lateral movement,
  collection). Every objective is `requires_approval` and blocked pending
  explicit authorization; the agent never self-executes.

These agents are selected by the CLI `--profile` flag: `recon` (default) runs
recon + vulnerability + planning + QA; `appsec` adds the web and API agents;
`full` adds the exploitation and post-exploitation agents. The `full` profile
reads an operator exploit plan from `--exploit-plan <file.json>`.

## Honest-output contract

Agents never fabricate findings. Every result is one of three kinds:

1. **Tool-sourced** — tagged `source="tool:<name>"`; produced from real tool
   output. SQL-injection findings are additionally tagged `validated=True`.
2. **DNS-sourced** — tagged `source="dns:getaddrinfo"` for host resolution.
3. **Advisory hypothesis** — tagged `source="llm_hypothesis"` and
   `validated=False`; a model-generated suggestion to investigate, never a
   confirmed finding.

When a required tool wrapper is not registered (or a model is absent for
hypotheses), the agent records an explicit `*_status` note in `context_updates`
(for example `port_scan_status="no_scanner_tool_registered"`) and returns no
findings — it does not invent data.

Agents treat model output as untrusted recommendations. Tool execution remains
subject to scope validation, approval policy, timeout protection, and sandbox
policy. Active scanning requires human approval; dry-run previews (which execute
nothing) do not.

