"""Tool prerequisite and runtime-policy regression tests."""

from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools.nmap_tool import NmapTool
from networkforgeai.tools.preflight import preflight_tool


def test_dry_run_preflight_checks_scope_and_skips_host_binary():
    tool = NmapTool(dry_run=True, sandbox_mode=False)
    tool.scope_policy = ScopePolicy(["example.com"])
    report = preflight_tool(tool, "example.com")
    assert report["ok"] is True
    assert any(check["status"] == "skipped" for check in report["checks"])


def test_preflight_fails_out_of_scope_before_command_checks():
    tool = NmapTool(dry_run=True, sandbox_mode=False)
    tool.scope_policy = ScopePolicy(["example.com"])
    report = preflight_tool(tool, "outside.example")
    assert report["ok"] is False
    assert report["status"] == "failed"
