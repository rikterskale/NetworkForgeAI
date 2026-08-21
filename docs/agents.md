# Agents

Agents inherit from `BaseAgent` and receive an approval gateway, message bus,
knowledge base context, optional model adapter, and registered tools.

The core agents are:

- `ReconAgent` for passive discovery and approved active reconnaissance.
- `VulnerabilityScannerAgent` for approved validation workflows.
- Planning, reporting, QA, web, API, exploitation, and post-exploitation interfaces
  in `networkforgeai.agents.specialized`.

Agents must treat model output as untrusted recommendations. Tool execution remains
subject to scope validation, approval policy, timeout protection, and sandbox policy.

