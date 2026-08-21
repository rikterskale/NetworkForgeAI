"""Safe specialized agents for planning, reporting, and validation workflows."""

from __future__ import annotations

from typing import Any, Dict, List

from ..core.base_agent import AgentStatus, BaseAgent


class ContextAgent(BaseAgent):
    capability = "context_analysis"

    def get_capabilities(self) -> List[str]:
        return [self.capability]


class PlanningAgent(ContextAgent):
    capability = "attack_path_planning"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        vulnerabilities = context.get("vulnerabilities", [])
        paths = [{"stage": 1, "finding": item.get("title", item.get("type", "finding")),
                  "requires_approval": True} for item in vulnerabilities]
        self.status = AgentStatus.COMPLETED
        return {"task": task, "findings": [], "context_updates": {"attack_paths": paths}}


class ReportingAgent(ContextAgent):
    capability = "reporting"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        findings = list(context.get("findings", []))
        self.status = AgentStatus.COMPLETED
        return {"task": task, "findings": findings, "context_updates": {"report_ready": True}}


class QualityAssuranceAgent(ContextAgent):
    capability = "quality_assurance"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in context.get("findings", []):
            key = (str(finding.get("type", "")), str(finding.get("target", "")))
            unique.setdefault(key, finding)
        self.status = AgentStatus.COMPLETED
        return {"task": task, "findings": list(unique.values()),
                "context_updates": {"deduplicated_findings": list(unique.values())}}


class WebApplicationAgent(ContextAgent):
    capability = "web_application_testing"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        urls = context.get("discovered_urls", [])
        self.status = AgentStatus.COMPLETED
        return {"task": task, "findings": [],
                "context_updates": {"web_targets_reviewed": urls, "active_testing_requires_approval": True}}


class APISecurityAgent(ContextAgent):
    capability = "api_security_testing"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.RUNNING
        self.status = AgentStatus.COMPLETED
        return {"task": task, "findings": [],
                "context_updates": {"api_testing_plan": {"requires_approval": True}}}


class NetworkExploitationAgent(ContextAgent):
    capability = "exploitation"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.WAITING_APPROVAL
        return {"task": task, "findings": [],
                "context_updates": {"exploitation_blocked": True}}


class PostExploitationAgent(ContextAgent):
    capability = "post_exploitation"

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        self.status = AgentStatus.WAITING_APPROVAL
        return {"task": task, "findings": [],
                "context_updates": {"post_exploitation_blocked": True}}

