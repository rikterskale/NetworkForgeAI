# Approval System

High- and critical-risk tools fail closed unless an approval gateway is attached and
the request is approved. Approval requests include the agent/tool, target, risk level,
description, expiry, and audit metadata.

The emergency stop cancels pending approvals and blocks new approval requests until
explicitly reset. Approval audit records are written as JSONL when an audit path is
configured. Records include a tool command digest when applicable and chained
`audit_previous_hash`/`audit_hash` fields so edits or truncation can be detected.
Approval details and command output are redacted before being emitted to operator
logs or persisted audit records.

Do not bypass the gateway by invoking an underlying command directly. Host execution
must be explicitly selected for development; production execution should use the
Docker sandbox runner.
