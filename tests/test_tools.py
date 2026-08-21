import pytest

from networkforgeai.tools import NmapTool, HydraTool
from networkforgeai.core.scope import ScopePolicy


def test_tool_requires_explicit_scope():
    tool = NmapTool(dry_run=True)
    with pytest.raises(ValueError):
        tool.execute("example.com")


def test_dry_run_builds_command_without_external_execution():
    tool = NmapTool(dry_run=True)
    tool.scope_policy = ScopePolicy(["example.com"])
    result = tool.execute("example.com")
    assert result.success
    assert "[DRY RUN]" in result.stdout


def test_high_risk_tool_cannot_execute_without_gateway():
    tool = HydraTool()
    tool.scope_policy = ScopePolicy(["example.com"])
    with pytest.raises(PermissionError):
        tool.execute("example.com", {"username": "user", "password": "pass"})


def test_sandbox_execution_fails_closed_without_configured_image():
    tool = NmapTool()
    tool.scope_policy = ScopePolicy(["example.com"])
    result = tool.execute("example.com")
    assert result.exit_code == -1
    assert "SANDBOX_IMAGE" in result.stderr
