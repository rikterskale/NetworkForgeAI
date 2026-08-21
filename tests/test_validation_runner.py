import pytest

from networkforgeai.core.approval_gateway import ApprovalGateway
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.core.validation_runner import ExploitValidationRunner
from networkforgeai.reporting.models import Finding, FindingStatus
from networkforgeai.sandbox.runner import SandboxRunner, SandboxUnavailable


class FakeSandbox:
    """Records executed commands instead of touching Docker."""

    def __init__(self, returncode: int = 0):
        self.executed: list[list[str]] = []
        self.returncode = returncode

    def run(self, command, *, timeout):
        self.executed.append(list(command))

        class Completed:
            stdout = "ok"
            stderr = ""

        completed = Completed()
        completed.returncode = self.returncode
        return completed


def _auto_approve_gateway() -> ApprovalGateway:
    """Manual gateway that approves via callback, simulating an instant human."""
    gateway = ApprovalGateway(mode="manual")

    async def approve_immediately(request):
        await gateway.approve(request.id, "test_operator")

    gateway.register_callback("auto", approve_immediately)
    return gateway


def _finding(target: str = "example.com") -> Finding:
    return Finding(type="sql_injection", target=target, title="SQLi", severity="high")


def _runner(sandbox=None, gateway=None) -> ExploitValidationRunner:
    policy = ScopePolicy(["example.com"])
    return ExploitValidationRunner(
        sandbox=sandbox or FakeSandbox(),
        gateway=gateway or ApprovalGateway(mode="manual"),
        scope_policy=policy,
        timeout_seconds=5,
    )


@pytest.mark.asyncio
async def test_requires_approved_gateway_and_scope():
    runner = _runner()
    outcome = await runner.validate_finding(_finding(), [["echo", "hi"]])
    # manual gateway with no human decision -> not approved, nothing executed
    assert outcome.executed is False
    assert outcome.approved is False
    assert "not granted" in outcome.reason


@pytest.mark.asyncio
async def test_rejects_out_of_scope_target_without_approval():
    gateway = ApprovalGateway(mode="manual")
    sandbox = FakeSandbox()
    runner = _runner(sandbox=sandbox, gateway=gateway)
    outcome = await runner.validate_finding(_finding("evil.example.net"), [["echo"]])
    assert outcome.executed is False
    assert sandbox.executed == []
    assert gateway.get_pending_requests() == []


@pytest.mark.asyncio
async def test_empty_commands_short_circuits():
    outcome = await _runner().validate_finding(_finding(), [])
    assert outcome.executed is False
    assert "no PoC" in outcome.reason


@pytest.mark.asyncio
async def test_approved_run_executes_in_sandbox():
    gateway = _auto_approve_gateway()
    sandbox = FakeSandbox(returncode=0)
    runner = _runner(sandbox=sandbox, gateway=gateway)
    outcome = await runner.validate_finding(
        _finding(), [["nmap", "-sV", "example.com"], ["curl", "example.com"]]
    )
    assert outcome.executed is True and outcome.approved is True
    assert len(outcome.command_results) == 2
    assert outcome.succeeded is True
    assert outcome.suggested_status is FindingStatus.VALIDATED
    assert sandbox.executed == [["nmap", "-sV", "example.com"], ["curl", "example.com"]]


@pytest.mark.asyncio
async def test_failed_commands_suggest_suspected():
    gateway = _auto_approve_gateway()
    sandbox = FakeSandbox(returncode=2)
    runner = _runner(sandbox=sandbox, gateway=gateway)
    outcome = await runner.validate_finding(_finding(), [["false"]])
    assert outcome.succeeded is False
    assert outcome.suggested_status is FindingStatus.SUSPECTED


@pytest.mark.asyncio
async def test_sandbox_errors_are_captured_not_raised():
    class BrokenSandbox(SandboxRunner):
        def run(self, command, *, timeout):
            raise SandboxUnavailable("no docker")

    gateway = _auto_approve_gateway()
    runner = _runner(sandbox=BrokenSandbox(), gateway=gateway)
    outcome = await runner.validate_finding(_finding(), [["echo"]])
    assert outcome.executed is True
    assert "SandboxUnavailable" in outcome.command_results[0]["error"]
    assert outcome.command_results[0]["returncode"] is None
