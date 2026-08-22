"""VAL-002: exploit validation runner.

Executes advisory proof-of-concept checks for a finding inside the Docker
sandbox, strictly behind the human approval gateway. Fails closed: without an
approved request, a configured sandbox, and an in-scope target, nothing runs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..reporting.models import Finding, FindingStatus
from ..sandbox.runner import SandboxRunner
from .approval_gateway import ApprovalGateway, ApprovalStatus, RiskLevel, action_requires_approval
from .scope import ScopePolicy

__all__ = ["ValidationOutcome", "ExploitValidationRunner"]


@dataclass(frozen=True)
class ValidationOutcome:
    """Result of a sandboxed PoC validation run."""

    finding_id: str
    executed: bool
    approved: bool
    reason: str
    command_results: list[dict[str, Any]] = field(default_factory=list)
    suggested_status: FindingStatus = FindingStatus.SUSPECTED

    @property
    def succeeded(self) -> bool:
        return self.executed and any(
            result.get("returncode") == 0 for result in self.command_results
        )


class ExploitValidationRunner:
    """Run approved PoC commands against a finding inside the sandbox.

    Safety contract (fail closed at every step):
    1. An approval gateway and sandbox runner must be configured.
    2. The finding target must be inside the explicit scope policy.
    3. A HIGH-risk approval request is submitted and awaited; execution only
       proceeds when the human decision is APPROVED before expiry.
    """

    def __init__(
        self,
        sandbox: SandboxRunner,
        gateway: ApprovalGateway,
        scope_policy: ScopePolicy,
        *,
        timeout_seconds: int = 120,
    ):
        self.sandbox = sandbox
        self.gateway = gateway
        self.scope_policy = scope_policy
        self.timeout_seconds = timeout_seconds

    async def validate_finding(
        self,
        finding: Finding,
        poc_commands: list[list[str]],
        *,
        requester_id: str = "validation_runner",
        justification: str | None = None,
    ) -> ValidationOutcome:
        """Validate a single finding with the given PoC command vectors."""
        if not poc_commands:
            return ValidationOutcome(
                finding_id=finding.finding_id,
                executed=False,
                approved=False,
                reason="no PoC commands supplied",
            )
        if not self.scope_policy.contains(finding.target):
            return ValidationOutcome(
                finding_id=finding.finding_id,
                executed=False,
                approved=False,
                reason=f"target outside scope policy: {finding.target}",
            )

        if not action_requires_approval(RiskLevel.HIGH, "exploitation"):
            return ValidationOutcome(
                finding_id=finding.finding_id,
                executed=False,
                approved=False,
                reason="validation policy did not require approval",
            )
        details: dict[str, Any] = {
            "finding_id": finding.finding_id,
            "commands": len(poc_commands),
            "category": "exploitation",
            "destructive": False,
        }
        if justification:
            details["justification"] = justification
        request = await self.gateway.request_approval(
            agent_id=requester_id,
            action_type="exploit_validation",
            description=f"Validate {finding.type} on {finding.target}",
            target=finding.target,
            risk_level=RiskLevel.HIGH,
            details=details,
            timeout_seconds=self.timeout_seconds,
        )
        decision = await self.gateway.wait_for_approval(request.id, poll_interval=0.05)
        if decision.status is not ApprovalStatus.APPROVED:
            return ValidationOutcome(
                finding_id=finding.finding_id,
                executed=False,
                approved=False,
                reason=f"approval not granted: {decision.status.value}",
            )

        command_results = [self._run_command(command, finding) for command in poc_commands]
        suggested = (
            FindingStatus.VALIDATED
            if any(r.get("returncode") == 0 for r in command_results)
            else FindingStatus.SUSPECTED
        )
        return ValidationOutcome(
            finding_id=finding.finding_id,
            executed=True,
            approved=True,
            reason="executed in sandbox after approval",
            command_results=command_results,
            suggested_status=suggested,
        )

    def _run_command(self, command: list[str], finding: Finding) -> dict[str, Any]:
        """Execute one command vector in the sandbox with timeout protection."""
        started = time.monotonic()
        try:
            completed = self.sandbox.run(command, timeout=self.timeout_seconds)
        except Exception as exc:  # sandbox unavailable, timeout, etc.
            return {
                "command": list(command),
                "error": f"{type(exc).__name__}: {exc}",
                "duration_ms": int((time.monotonic() - started) * 1000),
                "finding_id": finding.finding_id,
                "returncode": None,
            }
        return {
            "command": list(command),
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
            "returncode": completed.returncode,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "finding_id": finding.finding_id,
        }
