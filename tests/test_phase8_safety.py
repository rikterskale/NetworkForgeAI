import asyncio
import json
import subprocess

import pytest

from networkforgeai.core.approval_gateway import ApprovalGateway, ApprovalStatus, RiskLevel
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools.base_tool import BaseTool, ToolCategory, ToolRiskLevel


class HighRiskTool(BaseTool):
    name = "high-risk-test"
    category = ToolCategory.EXPLOITATION
    risk_level = ToolRiskLevel.HIGH

    def build_command(self, target, options=None):
        return ["validator", target]

    def parse_findings(self, stdout, stderr):
        return []


def test_scope_policy_handles_urls_wildcards_and_exclusions():
    policy = ScopePolicy(
        allowed=["*.example.com", "192.0.2.0/24"],
        excluded=["admin.example.com"],
    )

    assert policy.contains("https://api.example.com/v1")
    assert not policy.contains("https://admin.example.com/login")
    assert policy.contains("192.0.2.42")
    assert not policy.contains("198.51.100.42")


def test_high_risk_tool_fails_closed_without_approval_gateway():
    tool = HighRiskTool(
        sandbox_mode=False,
        scope_policy=ScopePolicy(["example.com"]),
    )

    with pytest.raises(PermissionError, match="approval gateway"):
        tool.execute("example.com")


def test_dry_run_is_safe_for_high_risk_tool(monkeypatch):
    tool = HighRiskTool(
        sandbox_mode=False,
        dry_run=True,
        scope_policy=ScopePolicy(["example.com"]),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("executed")),
    )

    result = tool.execute("example.com")

    assert result.success
    assert "DRY RUN" in result.stdout


def test_approval_audit_log_records_terminal_state(tmp_path):
    async def scenario():
        audit_path = tmp_path / "audit.jsonl"
        gateway = ApprovalGateway("manual", audit_path)
        request = await gateway.request_approval(
            "agent", "validate", "safe test", "example.com", RiskLevel.HIGH
        )
        assert await gateway.reject(request.id, "operator", "out of window")
        result = await gateway.wait_for_approval(request.id, poll_interval=0)

        assert result.status is ApprovalStatus.REJECTED
        records = [json.loads(line) for line in audit_path.read_text().splitlines()]
        assert records[-1]["status"] == ApprovalStatus.REJECTED.value
        assert records[-1]["rejection_reason"] == "out of window"

    asyncio.run(scenario())


def test_approval_gateway_handles_concurrent_low_risk_requests(tmp_path):
    async def scenario():
        gateway = ApprovalGateway("moderate", tmp_path / "audit.jsonl")
        requests = await asyncio.gather(
            *(
                gateway.request_approval(
                    "agent", "recon", f"request-{index}", "example.com", RiskLevel.LOW
                )
                for index in range(25)
            )
        )

        assert len({request.id for request in requests}) == 25
        assert all(request.status is ApprovalStatus.APPROVED for request in requests)
        assert len(gateway.get_pending_requests()) == 0

    asyncio.run(scenario())
