import asyncio
import subprocess
from types import SimpleNamespace

import pytest

from networkforgeai.agents.recon_agent import ReconAgent
from networkforgeai.agents.vuln_scanner_agent import VulnerabilityScannerAgent
from networkforgeai.core.approval_gateway import (
    ApprovalGateway,
    ApprovalRequest,
    ApprovalStatus,
    RiskLevel,
)
from networkforgeai.core.base_agent import AgentStatus
from networkforgeai.core.message_bus import MessageBus
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.sandbox.runner import SandboxRunner, SandboxUnavailable
from networkforgeai.tools import get_available_tools, get_tool_by_name
from networkforgeai.tools.base_tool import BaseTool, ToolCategory, ToolRiskLevel


class FakeTool(BaseTool):
    name = "fake"
    category = ToolCategory.REPORTING
    risk_level = ToolRiskLevel.LOW

    def build_command(self, target, options=None):
        return ["fake", target]

    def parse_findings(self, stdout, stderr):
        return [{"type": "x", "password": "secret"}]


def run(coro):
    return asyncio.run(coro)


def test_base_tool_execution_validation_and_errors(monkeypatch):
    tool = FakeTool(sandbox_mode=False, scope_policy=ScopePolicy(["example.com"]))
    assert not tool.validate_target("")
    assert not tool.validate_target("outside.example")
    assert tool.validate_target("example.com")
    assert tool.get_info()["name"] == "fake"
    assert tool.parse_findings("", "")
    assert (
        tool._sanitize_finding({"password": "x", "token": "y", "ok": 1})["password"] == "[REDACTED]"
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert tool.execute("example.com", timeout=1).success

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="bad"),
    )
    failed = tool.execute("example.com")
    assert failed.exit_code == 2
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("fake", 1)),
    )
    timed = tool.execute("example.com")
    assert timed.exit_code == -1
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    errored = tool.execute("example.com")
    assert "boom" in errored.stderr

    sandbox = FakeTool(sandbox_mode=True, scope_policy=ScopePolicy(["example.com"]))
    monkeypatch.setattr(
        "networkforgeai.tools.base_tool.SandboxRunner.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert sandbox.execute("example.com").success


def test_sandbox_runner_fail_closed_and_docker_command(monkeypatch):
    with pytest.raises(SandboxUnavailable):
        SandboxRunner().run(["nmap"], timeout=1)
    monkeypatch.setenv("NETWORKFORGE_SANDBOX_IMAGE", "image:ci")
    monkeypatch.setattr("networkforgeai.sandbox.runner.shutil.which", lambda name: None)
    with pytest.raises(SandboxUnavailable):
        SandboxRunner().run(["nmap"], timeout=1)
    monkeypatch.setattr(
        "networkforgeai.sandbox.runner.shutil.which", lambda name: "/usr/bin/docker"
    )
    calls = {}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: calls.setdefault("command", command) or SimpleNamespace(),
    )
    SandboxRunner().run(["nmap", "example.com"], timeout=1)
    assert "--network" in calls["command"]


def test_approval_defensive_paths_and_callback_errors(tmp_path):
    async def scenario():
        gateway = ApprovalGateway("moderate", tmp_path / "audit.jsonl")

        async def bad_callback(request):
            raise RuntimeError("callback")

        gateway.register_callback("bad", bad_callback)
        low = await gateway.request_approval("a", "scan", "d", "t", RiskLevel.LOW)
        assert low.status is ApprovalStatus.APPROVED
        assert not await gateway.approve("missing", "x")
        assert not await gateway.reject("missing", "x", "no")
        assert not await gateway.reject(low.id, "x", "already done")
        with pytest.raises(ValueError):
            await gateway.wait_for_approval("missing")
        pending = await gateway.request_approval("a", "scan", "d", "t", RiskLevel.HIGH)
        await gateway.emergency_stop("stop")
        assert (await gateway.wait_for_approval(pending.id)).status is ApprovalStatus.CANCELLED

    run(scenario())


def test_agent_message_and_approval_branches():
    async def scenario():
        agent = ReconAgent()
        with pytest.raises(RuntimeError):
            await agent.send_message("x", {})
        assert await agent.receive_message(timeout=0.01) is None
        bus = MessageBus()
        agent.message_bus = bus
        await bus.register(agent.id)
        assert await agent.receive_message(timeout=0.001) is None
        await bus.unregister(agent.id)
        with pytest.raises(ValueError):
            await agent.send_message("missing", {})

        class Gateway:
            async def request_approval(self, **kwargs):
                return ApprovalRequest(id="x")

            async def wait_for_approval(self, request_id):
                return ApprovalRequest(id=request_id, status=ApprovalStatus.REJECTED)

        agent.approval_gateway = Gateway()
        assert await agent.request_approval("x", "d", "t", RiskLevel.LOW) == (False, None)
        assert agent.status is AgentStatus.IDLE

    run(scenario())


def test_registry_exports_and_recon_empty_paths():
    assert len(get_available_tools()) == 12
    assert get_tool_by_name("graphql-probe").name == "graphql-probe"
    assert get_tool_by_name("nmap").name == "nmap"
    with pytest.raises(ValueError):
        get_tool_by_name("missing")

    async def scenario():
        recon = ReconAgent()
        assert (await recon.execute("enumerate_subdomains", {}))["findings"] == []
        assert (await recon.execute("fingerprint_services", {}))["findings"] == []
        scanner = VulnerabilityScannerAgent()

        async def reject(*args, **kwargs):
            return False, None

        scanner.request_approval = reject
        assert (await scanner.execute("scan_auth_bypass", {}))["findings"] == []

    run(scenario())


def test_approval_request_round_trips_legacy_naive_timestamps():

    request = ApprovalRequest(
        agent_id="a1",
        action_type="exploit",
        description="d",
        target="t",
    )
    data = request.to_dict()
    # Simulate state persisted before the UTC migration: naive ISO timestamps.
    data["created_at"] = data["created_at"].replace("+00:00", "")

    restored = ApprovalRequest.from_dict(data)
    assert restored.created_at.tzinfo is not None
    assert restored.created_at == request.created_at


def test_orchestrator_compat_import_path():
    """The legacy import path must keep re-exporting the core gateway."""
    from networkforgeai.core.approval_gateway import ApprovalGateway as CoreGateway
    from networkforgeai.orchestrator.approval_gateway import (
        ApprovalGateway as CompatGateway,
    )

    assert CompatGateway is CoreGateway
