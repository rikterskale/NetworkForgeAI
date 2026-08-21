"""Tests for terminal UI components (TUI-001..004)."""

import io

import pytest

from networkforgeai.core.approval_gateway import ApprovalGateway, ApprovalRequest, RiskLevel
from networkforgeai.interface.tui import (
    ApprovalDialog,
    InteractiveMenu,
    LogStreamPanel,
    TUIDisplay,
)


def test_display_progress_and_table():
    stream = io.StringIO()
    display = TUIDisplay(stream=stream, colors=False)
    bar = display.progress(7, 10, "tasks")
    assert "70%" in bar and "7/10" in bar
    assert display.progress(1, 0) == "[------------------------]   0% 1/0 tasks"
    table = display.table(["agent", "status"], [("recon", "WORKING"), ("qa", "IDLE")])
    lines = table.splitlines()
    assert len(lines) == 4 and "agent" in lines[0] and "---" in lines[1]
    display.show("hello")
    assert "hello" in stream.getvalue()


def test_display_colors_when_enabled():
    stream = io.StringIO()
    display = TUIDisplay(stream=stream, colors=True)
    rendered = display.table(["h"], [["x"]])
    assert "\033[36m" in rendered


def test_log_stream_panel_levels():
    stream = io.StringIO()
    panel = LogStreamPanel(stream=stream, colors=False)
    panel.log("recon", "scan finished")
    panel.log("exploit", "ERROR: exploit failed")
    panel.log("gateway", "approval required for action")
    panel.log("ops", "warning: slow response")
    tags = [tag for _, tag, _ in panel.entries]
    assert tags == ["INFO", "ERROR", "APPROVAL", "WARN"]
    out = stream.getvalue()
    assert "recon: scan finished" in out and "[ERROR]" in out


def test_log_stream_panel_colors():
    panel = LogStreamPanel(stream=io.StringIO(), colors=True)
    line = panel.log("a", "error occurred")
    assert line.startswith("\033[31m") and line.endswith("\033[0m")


def test_interactive_menu_selects_action():
    menu = InteractiveMenu(
        "Scan",
        [("start", lambda: "started"), ("stop", None)],
        instream=io.StringIO("1\n"),
        outstream=io.StringIO(),
        interactive=True,
    )
    assert menu.run() == "started"


def test_interactive_menu_quit_and_invalid_then_valid():
    menu = InteractiveMenu(
        "Scan",
        [("one", lambda: 1), ("two", lambda: 2)],
        instream=io.StringIO("9\nzz\n2\n"),
        outstream=io.StringIO(),
        interactive=True,
    )
    assert menu.run() == 2


def test_interactive_menu_eof_fails_closed():
    menu = InteractiveMenu(
        "Scan",
        [("one", lambda: 1)],
        instream=io.StringIO(""),
        outstream=io.StringIO(),
        interactive=True,
    )
    assert menu.run() is None


def test_interactive_menu_non_interactive_disabled(capsys):
    out = io.StringIO()
    menu = InteractiveMenu(
        "Scan", [("one", lambda: 1)], instream=io.StringIO(), outstream=out, interactive=False
    )
    assert menu.run() is None
    assert "menu disabled" in out.getvalue()
    empty = InteractiveMenu("Empty", [], outstream=out, interactive=True)
    assert empty.run() is None


@pytest.mark.asyncio
async def test_approval_dialog_approve_and_reject_paths():
    gateway = ApprovalGateway(mode="manual")
    approved = ApprovalRequest(
        agent_id="a",
        action_type="port_scan",
        description="d",
        target="example.com",
        risk_level=RiskLevel.HIGH,
    )
    gateway.requests[approved.id] = approved
    dialog = ApprovalDialog(gateway, stream=io.StringIO(), interactive=True, operator="op")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.input", lambda _: "y")
        await dialog(approved)
    assert approved.status.value == "approved"

    rejected = ApprovalRequest(
        agent_id="a",
        action_type="exploit",
        description="d",
        target="example.com",
        risk_level=RiskLevel.CRITICAL,
    )
    gateway.requests[rejected.id] = rejected
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.input", lambda _: "")
        await dialog(rejected)
    assert rejected.status.value == "rejected"


@pytest.mark.asyncio
async def test_approval_dialog_non_interactive_stays_pending():
    gateway = ApprovalGateway(mode="manual")
    request = ApprovalRequest(
        agent_id="a",
        action_type="brute_force",
        description="d",
        target="example.com",
        risk_level=RiskLevel.HIGH,
    )
    gateway.requests[request.id] = request
    dialog = ApprovalDialog(gateway, stream=io.StringIO(), interactive=False)
    await dialog(request)
    assert request.status.value == "pending"
    rendered = dialog.render(request)
    assert "Non-interactive" in rendered


@pytest.mark.asyncio
async def test_approval_dialog_eof_rejects():
    gateway = ApprovalGateway(mode="manual")
    request = ApprovalRequest(
        agent_id="a",
        action_type="port_scan",
        description="d",
        target="example.com",
        risk_level=RiskLevel.HIGH,
    )
    gateway.requests[request.id] = request
    dialog = ApprovalDialog(gateway, stream=io.StringIO(), interactive=True)

    def raise_eof(_: object) -> str:
        raise EOFError

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.input", raise_eof)
        await dialog(request)
    assert request.status.value == "rejected"
