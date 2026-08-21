import io

import pytest

from networkforgeai.core.approval_gateway import ApprovalGateway, ApprovalRequest, RiskLevel
from networkforgeai.interface.cli_ui import ApprovalPrompt, StatusDisplay


def test_status_display_tracks_transitions_and_renders():
    stream = io.StringIO()
    display = StatusDisplay(stream=stream)
    display.update("recon-1", "running")
    display.update("recon-1", "idle")
    display.update("recon-1", "idle")
    assert display.events == [("recon-1", "running"), ("recon-1", "idle")]
    rendered = display.render()
    assert rendered == "recon-1  idle"
    assert "[status] recon-1: unknown -> running" in stream.getvalue()


@pytest.mark.asyncio
async def test_approval_prompt_fail_closed_without_tty(monkeypatch):
    gateway = ApprovalGateway(mode="manual")
    stream = io.StringIO()
    prompt = ApprovalPrompt(gateway, stream=stream, interactive=False)
    request = ApprovalRequest(
        agent_id="agent",
        action_type="exploit_attempt",
        description="probe",
        target="example.com",
        risk_level=RiskLevel.HIGH,
    )
    await prompt(request)
    output = stream.getvalue()
    assert "Non-interactive session" in output


@pytest.mark.asyncio
async def test_approval_prompt_interactive_answers(monkeypatch):
    for answer, expected in (("y", "approved"), ("n", "rejected"), ("garbage", "rejected")):
        gateway = ApprovalGateway(mode="manual")
        prompt = ApprovalPrompt(gateway, stream=io.StringIO(), interactive=True)
        monkeypatch.setattr("builtins.input", lambda *_: answer)
        request = ApprovalRequest(
            agent_id="agent",
            action_type="exploit_attempt",
            description="probe",
            target="example.com",
            risk_level=RiskLevel.HIGH,
        )
    gateway.requests[request.id] = request
    await prompt(request)
    assert gateway.get_request(request.id).status.value == expected


@pytest.mark.asyncio
async def test_approval_prompt_eof_rejects(monkeypatch):
    gateway = ApprovalGateway(mode="manual")
    prompt = ApprovalPrompt(gateway, stream=io.StringIO(), interactive=True)

    def raise_eof(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    request = ApprovalRequest(
        agent_id="agent",
        action_type="exploit_attempt",
        description="probe",
        target="example.com",
        risk_level=RiskLevel.HIGH,
    )
    gateway.requests[request.id] = request
    await prompt(request)
    assert gateway.get_request(request.id).status.value == "rejected"
