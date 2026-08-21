# Architecture Overview

NetworkForgeAI is a host-side multi-agent reasoning system with a mandatory
human approval gateway, one shared per-scan offensive sandbox, per-agent
persistent model sessions, and disk-backed evidence consumed by every
interface.

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
├── tools/              # BaseTool framework + 8 tool integrations
├── sandbox/            # fail-closed Docker command runner
├── reporting/          # finding model, format generators, compliance maps
├── integrations/       # webhooks, Slack/Jira notifications
└── interface/          # CLI UI helpers, dashboard API, operator console
```

## Execution flow

1. **CLI bootstrap** (`cli.py`): parses arguments, builds a `ScopePolicy` from
   `--scope`/`--exclude`, and refuses to proceed when the target is outside
   scope. Single-tool runs construct the tool directly; `--orchestrate` builds
   a `ScanOrchestrator`.
2. **Orchestration** (`core/orchestrator.py`): owns an `ApprovalGateway`,
   `MessageBus`, `KnowledgeBase`, and `TaskQueue`. Agents are registered with
   shared references to these. The scan runs in phases (reconnaissance,
   vulnerability scanning, exploitation, post-exploitation), executing each
   phase's agents concurrently.
3. **Agent execution**: agents call tools or the model adapter. Any HIGH/CRITICAL
   action goes through `BaseAgent.request_approval`, which submits to the
   gateway and blocks on the human decision.
4. **Tool execution** (`tools/base_tool.py`): commands are built, validated
   against scope, wrapped in dry-run/sandbox policy, and executed through
   `sandbox/runner.py`. Synchronous tools request approval via the gateway's
   async protocol before running.
5. **Evidence**: findings flow into the orchestrator's collection and are
   persisted as `scan_state.json`, `findings.{json,csv,sarif}`, and
   `report.md` under the scan directory.

## Safety model

Three independent layers, all fail-closed:

| Layer | Enforcement |
|-------|-------------|
| Scope | `ScopePolicy.contains()` gates every target before any action; exclusions win |
| Approval | `ApprovalGateway` blocks HIGH/CRITICAL actions until a human decides; emergency stop cancels pending work and blocks new requests |
| Sandbox | `SandboxRunner` runs commands in Docker with no network, dropped capabilities, and no-new-privileges; host execution requires explicit opt-in |

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
disk, including knowledge-base snapshot and task queue. Audit trails are
append-only JSONL (`approval_audit.jsonl`) and must be preserved.

## Typing and quality gates

The entire package passes `mypy --strict` (enforced in CI). Coverage floor is
90% with `cli.py`, the dashboard, and LLM adapters omitted from coverage
accounting. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full gate.
