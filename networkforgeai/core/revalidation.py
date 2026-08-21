"""Automated remediation re-testing plans (ADV-105).

Builds approval-gated verification actions for findings marked as remediated
so operators can re-validate fixes with the existing tool inventory. Planning
is a pure computation; executing any action still goes through the normal
scope and human-approval path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..reporting.models import prepare_findings
from .validation import FindingStatus

__all__ = ["RetestAction", "build_retest_plan"]

_TOOL_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("sqli", "injection"), "sqlmap"),
    (("xss", "cross-site"), "owasp-zap"),
    (("header", "tls", "ssl", "https"), "nikto"),
    (("jwt",), "jwt-analyzer"),
    (("graphql",), "graphql-probe"),
    (("open-port", "port", "service", "network"), "nmap"),
    (("password", "credential", "brute"), "hydra"),
)

_STATUSES = ("remediated",)


@dataclass(frozen=True)
class RetestAction:
    """One planned verification step for a remediated finding."""

    finding_type: str
    target: str
    severity: str
    tool_name: str
    options: dict[str, str] = field(default_factory=dict)
    requires_approval: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_type": self.finding_type,
            "target": self.target,
            "severity": self.severity,
            "tool_name": self.tool_name,
            "options": dict(self.options),
            "requires_approval": self.requires_approval,
        }


def suggest_tool_for_finding(finding_type: str) -> str:
    """Pick the most relevant inventory tool for verifying a finding type."""
    lowered = finding_type.lower()
    for keywords, tool in _TOOL_HINTS:
        if any(keyword in lowered for keyword in keywords):
            return tool
    return "nikto"


def build_retest_plan(
    findings: list[dict[str, object]],
    statuses: set[str] | None = None,
) -> list[RetestAction]:
    """Plan re-tests for findings whose status is in ``statuses``.

    Defaults to ``{"remediated"}``. Every returned action requires explicit
    human approval; execution remains subject to scope policy enforcement at
    the tool boundary.
    """
    allowed = statuses or set(_STATUSES)
    plan: list[RetestAction] = []
    for row in prepare_findings(findings):  # type: ignore[arg-type]
        status = str(row.get("status") or FindingStatus.SUSPECTED.value)
        if status not in allowed:
            continue
        finding_type = str(row.get("type") or "unknown")
        plan.append(
            RetestAction(
                finding_type=finding_type,
                target=str(row.get("target", "")),
                severity=str(row.get("severity", "informational")),
                tool_name=suggest_tool_for_finding(finding_type),
                options={"retest_of": str(row.get("finding_id", ""))},
            )
        )
    return plan
