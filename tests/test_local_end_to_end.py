"""Local deterministic end-to-end workflow coverage.

This test never contacts an external target. It exercises a real subprocess
through the tool wrapper, agent, orchestrator, persistence, and report layers.
"""

import json
import sys
from typing import Any, Dict, List, Optional

import pytest

from networkforgeai.core.base_agent import BaseAgent
from networkforgeai.core.orchestrator import ScanConfig, ScanOrchestrator
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools.base_tool import BaseTool, ToolCategory, ToolRiskLevel


class FixtureScanner(BaseTool):
    name = "fixture-scanner"
    category = ToolCategory.REPORTING
    risk_level = ToolRiskLevel.LOW

    def __init__(self, *, scope_policy: ScopePolicy):
        super().__init__(sandbox_mode=False, scope_policy=scope_policy)

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        payload = json.dumps(
            {
                "type": "fixture_observation",
                "title": "Deterministic local fixture observation",
                "target": target,
                "severity": "informational",
                "description": "Produced by the local end-to-end fixture.",
                "source": "tool:fixture-scanner",
            }
        )
        return [sys.executable, "-c", "print(" + repr(payload) + ")"]

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        return [json.loads(stdout.strip())]


class FixtureAgent(BaseAgent):
    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        result = await self.run_tool("fixture-scanner", context["target"])
        assert result is not None
        return {"task": task, "findings": result.findings, "context_updates": {}}

    def get_capabilities(self) -> List[str]:
        return ["reconnaissance"]


@pytest.mark.asyncio
async def test_local_fixture_runs_through_agent_orchestrator_and_reports(tmp_path):
    target = "fixture.local"
    policy = ScopePolicy([target])
    scanner = FixtureScanner(scope_policy=policy)
    orchestrator = ScanOrchestrator(
        ScanConfig(
            target=target,
            scope=[target],
            save_dir=str(tmp_path),
            report_formats=["markdown", "json", "csv", "sarif", "pdf"],
        )
    )
    agent = FixtureAgent(tool_registry={scanner.name: scanner})
    orchestrator.register_agent(agent)

    await orchestrator.execute_scan()

    assert orchestrator.status.value == "completed"
    assert orchestrator.findings[0]["type"] == "fixture_observation"
    scan_dir = tmp_path / orchestrator.scan_id
    assert json.loads((scan_dir / "findings.json").read_text())[0]["target"] == target
    assert (scan_dir / "report.md").is_file()
    state = json.loads((scan_dir / "scan_state.json").read_text())
    assert state["config"]["scope"] == [target]
    assert state["config"]["report_formats"] == ["markdown", "json", "csv", "sarif", "pdf"]
