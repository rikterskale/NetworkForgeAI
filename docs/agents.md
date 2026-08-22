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
- Planning, reporting, QA, web, API, exploitation, and post-exploitation
  interfaces in `networkforgeai.agents.specialized`.

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

