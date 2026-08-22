# Feature maturity and evidence policy

NetworkForgeAI distinguishes implementation from operational maturity. A
feature must not be described as production-ready solely because a wrapper,
class, or unit test exists.

## Maturity levels

| Level | Evidence required |
|---|---|
| Implemented | Code exists and has a documented interface |
| Unit-tested | Deterministic unit tests cover the main behavior and failure paths |
| Integration-tested | The component has been tested with its real dependency or a contract-faithful fixture |
| End-to-end-tested | A complete local workflow exercises the component through the public runtime path |
| Production-hardened | Operational limits, security review, recovery, observability, compatibility, and release evidence exist |
| Advisory/foundation | The feature produces plans, hypotheses, or scaffolding and must not be treated as confirmed execution capability |

## Current project interpretation

- The scope policy, approval gateway, sandbox runner, report model, and core
  CLI paths have implementation and regression-test coverage.
- External scanner and provider integrations are wrappers unless their real
  dependency behavior is covered by an integration or contract test.
- LLM-generated hypotheses remain advisory unless independently validated by a
  tool or operator.
- Dashboard operator behavior requires a live orchestrator attachment; the
  default persisted-report dashboard is not equivalent to a live scan console.
- A capability marked implemented in the register does not automatically mean
  production-hardened.

## Claim policy

Documentation should use the most conservative applicable level. Terms such as
“production-ready,” “vendor-grade,” and “complete” require end-to-end and
production-hardening evidence, not only unit coverage.
