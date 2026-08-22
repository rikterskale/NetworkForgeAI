# Architecture Overview

NetworkForgeAI is a host-side multi-agent coordination system with a mandatory
human approval gateway. Agents drive real tool wrappers (and, optionally, an LLM
for advisory triage), execute commands through a fail-closed Docker runner, and
write disk-backed evidence consumed by every interface. Agents never fabricate
findings — see the honest-output contract in [Agents](agents.md).

## Package layout

```
networkforgeai/
├── cli.py              # argparse entry point (`networkforgeai` command)
├── config.py           # pydantic-settings, env-driven, safety-validated
├── core/               # safety + coordination (no I/O side effects by design)
│   ├── scope.py            # allow-list enforcement (domain/IP/CIDR/exclusions)
│   ├── approval_gateway.py # HITL decisions, audit JSONL, emergency stop
│   ├── orchestrator.py     # scan lifecycle, phases, state persistence
│   ├── base_agent.py       # agent contract: status, mailbox, findings
│   ├── message_bus.py      # inter-agent mailboxes
│   ├── knowledge_base.py   # shared discoveries, retrieval
│   ├── task_queue.py       # capability-matched task assignment
│   ├── validation.py       # advisory CVSS/PoC/FP/impact engine
│   └── validation_runner.py# sandbox-only approved PoC execution
├── agents/             # ReconAgent, VulnerabilityScannerAgent, specialized
├── models/             # LLM adapter layer (optional providers)
├── tools/              # BaseTool framework + tool integrations (nmap, sqlmap, ...)
├── sandbox/            # fail-closed Docker command runner
├── reporting/          # finding model, format generators, compliance maps
├── integrations/       # webhooks, Slack/Jira notifications
└── interface/          # CLI UI helpers, dashboard API, operator console
```

## Execution flow

1. **CLI bootstrap** (`cli.py`): loads environment configuration, applies
   explicit CLI overrides, builds a `ScopePolicy` from the resolved scope and
   `--exclude`, and refuses to proceed when the target is outside scope.
   Single-tool and orchestrated runs use the same resolved output directory,
   approval mode, report formats, and audit setting.
2. **Orchestration** (`core/orchestrator.py`): owns an `ApprovalGateway`,
   `MessageBus`, `KnowledgeBase`, and `TaskQueue`. Agents are registered with
   shared references to these. The scan runs in phases (reconnaissance,
   vulnerability scanning, exploitation, post-exploitation), executing each
   phase's agents concurrently.
3. **Agent execution**: agents run registered tool wrappers via
   `BaseAgent.run_tool` (which awaits `BaseTool.execute_async`) and, when a model
   is configured, request advisory hypotheses. Results are tagged by source and
   never fabricated; missing tools/models yield an explicit status note.
4. **Tool execution** (`tools/base_tool.py`): commands are built, validated
   against scope, and wrapped in dry-run/sandbox policy. Active actions use the
   centralized approval policy; HIGH/CRITICAL tools enforce their own gateway
   request, while direct CLI medium-risk actions are approved before execution.
   `execute_async` awaits the gateway on the running loop and offloads the
   subprocess to a worker thread.
5. **Evidence**: findings flow into the orchestrator's collection and are
   persisted as `scan_state.json`, `findings.{json,csv,sarif}`, and
   `report.md` under the scan directory.

## Safety model

Three independent layers, all fail-closed:

| Layer | Enforcement |
|-------|-------------|
| Scope | `ScopePolicy.contains()` gates every target before any action; exclusions win |
| Approval | `ApprovalGateway` blocks HIGH/CRITICAL actions until a human decides; emergency stop cancels pending work and blocks new requests |
| Sandbox | `SandboxRunner` runs commands in Docker locked down by default (`--network none`, `--cap-drop ALL`, no-new-privileges). Network egress and `NET_RAW`/`NET_ADMIN` are opt-in via `NETWORKFORGE_SANDBOX_NETWORK`/`_CAPS` (allowlisted, fail-closed). Host execution requires explicit opt-in |

The gateway never auto-approves HIGH/CRITICAL risk regardless of mode. Tests in
`tests/test_phase8_safety.py` enforce bypass prevention; treat changes there as
security-sensitive.

## Model adapter layer

`models/base_adapter.py` defines the provider-neutral contract (chat, stream,
capabilities, token accounting, context preparation). Provider adapters
(OpenAI, Anthropic, Google, Azure, LiteLLM, local) are optional imports: the
framework runs fully without them for deterministic workflows.
`ModelFactory.create_from_env` wires providers from environment variables.

## Interfaces

All interfaces consume the same disk-backed evidence:

- **CLI** — guided workflows, dry runs, report viewing.
- **Dashboard API** (`interface/dashboard.py`) — authenticated read-only
  surfaces always available; operator endpoints (approval queue, steering)
  enabled only when a live orchestrator is attached, and fail closed otherwise.
- **Operator console** (`GET /`) — dependency-free single-file page over the
  same JSON API.

## Persistence and recovery

Scan state is written after every phase transition and approval event
(`_save_state`). `ScanOrchestrator.from_state(scan_id)` restores a scan from
disk, including knowledge-base snapshot, task queue, terminal approval requests,
and `phase_errors`. Audit trails are append-only, hash-chained JSONL
(`approval_audit.jsonl`) and must be preserved.

## Typing and quality gates

CI runs `mypy --strict networkforgeai`. The maintained typed core, adapter,
agent, and dashboard surfaces are expected to remain clean; any temporary
exclusions must be explicit in configuration and tracked as debt. Coverage
floor is 90% and the LLM SDK adapters are unit-tested with fake clients. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the full gate.
