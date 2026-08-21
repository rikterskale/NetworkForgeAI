# Phases 1–4 Verification

This document records what is implemented and what still requires external
systems or provider credentials.

## Phase 1 — Foundation and safety

Complete in-repository capabilities:

- Installable Python package with CLI entry point.
- Environment configuration model with explicit target-scope validation.
- Scope matching for hostnames, wildcard hostnames, IP addresses, CIDRs, and exclusions.
- Unified approval gateway with risk levels, expiry, audit JSONL, auto-approval policy, and emergency stop.
- Docker Compose and Dockerfile references resolve to repository paths.

## Phase 2 — Orchestration and agents

Complete in-repository capabilities:

- Concurrent orchestrator with lifecycle transitions and cancellation.
- Asynchronous message bus with registered agent mailboxes.
- Shared thread-safe knowledge base.
- Capability-aware task records and task status tracking.
- Agent state, knowledge-base, task, finding, and approval persistence.
- Reconnaissance, vulnerability, planning, reporting, QA, web, API, exploitation,
  and post-exploitation agent interfaces.

## Phase 3 — Tool execution

Complete in-repository capabilities:

- Nmap, Masscan, Nikto, ZAP, SQLMap, Hydra, CrackMapExec, and Impacket command
  builders and parsers.
- Explicit scope enforcement at the tool boundary.
- High/critical-risk fail-closed approval enforcement.
- Docker sandbox runner that refuses host fallback when sandbox mode is enabled.
- Dry-run mode and timeout/error result handling.

External prerequisites:

- The corresponding binaries must be installed in the configured sandbox image.
- Metasploit, Burp, browser automation, cloud, Kubernetes, and Active Directory
  suites are not bundled and require separate approved integrations.

## Phase 4 — AI/LLM integration

Complete in-repository capabilities:

- Unified OpenAI, Anthropic, Google, Azure, local, and LiteLLM adapter interfaces.
- Provider factory and environment-based selection.
- Async-safe fallback creation and bounded retry utility.
- Streaming, tool definitions, token accounting, prompt templates, JSON parsing,
  context preparation, and model hooks on agents.

External prerequisites:

- Provider SDKs and credentials are required for live calls.
- Live provider compatibility and latency must be verified in an environment with
  the relevant SDKs and API access.

## Verification

The repository compiles successfully. Thirteen Phase 1–4 regression tests pass
through the lightweight test runner available in this environment. Native
pytest execution remains pending because pip and pytest are not installed on the
host.

