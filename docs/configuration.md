# Configuration

Copy `.env.example` to `.env` and replace all placeholders. `TARGET_SCOPE` is a
comma-separated allow-list of authorized domains, IPs, or CIDR ranges. An empty
scope denies tool execution.

Safety-critical settings:

- `APPROVAL_MODE=strict` is the recommended default.
- `BLOCK_DESTRUCTIVE_ACTIONS=true` must remain enabled.
- `DASHBOARD_AUTH_TOKEN` must be a random secret and is required for dashboard access.
- `NETWORKFORGE_SANDBOX_IMAGE` must identify a controlled tool image when sandbox mode is used.

Provider settings are optional for the non-LLM readiness gate. Live AI analysis requires
one provider key or a local LLM endpoint.

