"""Tests for the honest agent<->tool wiring introduced in the reasoning refactor.

These exercise the async tool boundary (approval + execution) and the agent
fallbacks that report explicit status instead of fabricating findings.
"""

import asyncio

import pytest

from networkforgeai.agents.recon_agent import ReconAgent
from networkforgeai.agents.vuln_scanner_agent import VulnerabilityScannerAgent
from networkforgeai.core.approval_gateway import ApprovalGateway, ApprovalStatus
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools.nmap_tool import NmapTool
from networkforgeai.tools.web_scanner_tools import SQLMapTool


def run(coro):
    return asyncio.run(coro)


def test_execute_async_scope_and_dry_run():
    async def scenario():
        tool = NmapTool(dry_run=True, sandbox_mode=False)
        tool.scope_policy = ScopePolicy(["example.com"])

        # Out-of-scope target is rejected before any execution.
        with pytest.raises(ValueError):
            await tool.execute_async("evil.test")

        result = await tool.execute_async("example.com")
        assert result.success
        assert "[DRY RUN]" in result.stdout

    run(scenario())


def test_execute_async_high_risk_requires_and_honors_approval():
    async def scenario():
        gateway = ApprovalGateway(mode="manual")

        async def auto_approve(request):
            if request.status is ApprovalStatus.PENDING:
                await gateway.approve(request.id, "test-operator")

        gateway.register_callback("auto", auto_approve)

        tool = SQLMapTool(dry_run=False, sandbox_mode=False)
        tool.scope_policy = ScopePolicy(["example.com"])
        tool.approval_gateway = gateway
        # Approved: proceeds to execution (sqlmap binary absent -> failed result,
        # but the approval path and command runner are exercised).
        result = await tool.execute_async("http://example.com/")
        assert result.tool_name == "sqlmap"

        # Rejection path raises PermissionError.
        reject_gateway = ApprovalGateway(mode="manual")

        async def auto_reject(request):
            if request.status is ApprovalStatus.PENDING:
                await reject_gateway.reject(request.id, "test-operator", "no")

        reject_gateway.register_callback("auto", auto_reject)
        tool.approval_gateway = reject_gateway
        with pytest.raises(PermissionError):
            await tool.execute_async("http://example.com/")

        # Missing gateway on a high-risk tool fails closed.
        tool.approval_gateway = None
        with pytest.raises(PermissionError):
            await tool.execute_async("http://example.com/")

    run(scenario())


def test_run_tool_returns_none_when_unregistered():
    async def scenario():
        agent = ReconAgent()
        assert agent.has_tool("nmap") is False
        assert await agent.run_tool("nmap", "example.com") is None

    run(scenario())


def test_recon_general_and_technology_paths():
    async def scenario():
        # detect_technologies with no fingerprint tool -> honest status.
        recon = ReconAgent()
        tech = await recon.execute("detect_technologies", {"target": "localhost"})
        assert tech["context_updates"]["technology_status"] == "no_fingerprint_tool_registered"

        # General task resolves the host and reports no scanner tool.
        general = await recon.execute("recon", {"target": "localhost"})
        assert general["context_updates"]["port_scan_status"] == "no_scanner_tool_registered"

    run(scenario())


def test_recon_scan_failure_is_reported_not_fabricated():
    class _FailingTool:
        name = "nmap"
        approval_gateway = None

        async def execute_async(self, target, options=None, timeout=300):
            class _R:
                success = False
                findings: list = []
                stderr = "boom"

            return _R()

    async def scenario():
        recon = ReconAgent(tool_registry={"nmap": _FailingTool()})

        async def approve(*args, **kwargs):
            return True, {}

        recon.request_approval = approve
        result = await recon.execute("scan_ports", {"target": "example.com"})
        assert result["findings"] == []
        assert result["context_updates"]["port_scan_status"] == "scan_failed"

    run(scenario())


def test_vuln_hypotheses_empty_without_model():
    async def scenario():
        scanner = VulnerabilityScannerAgent()
        assert await scanner.llm_hypotheses("prompt", {}) == []

    run(scenario())
