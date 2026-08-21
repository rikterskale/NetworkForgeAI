"""
Scan Orchestrator - Central coordinator for multi-agent penetration tests

Manages agent lifecycle, coordinates task distribution, enforces approval workflows,
and maintains shared context across all agents in a scan session.
"""

import asyncio
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..reporting import to_csv, to_json, to_sarif
from .approval_gateway import ApprovalGateway
from .base_agent import AgentState, AgentStatus, BaseAgent
from .knowledge_base import KnowledgeBase
from .message_bus import MessageBus
from .task_queue import AgentTask, TaskQueue


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class ScanConfig:
    """Configuration for a penetration test scan."""

    target: str
    scope: List[str] = field(default_factory=list)  # Allowed IP ranges, domains
    excluded: List[str] = field(default_factory=list)  # Excluded targets
    max_agents: int = 5
    approval_mode: str = "manual"  # manual, auto-low, auto-approved
    timeout_hours: int = 24
    save_dir: str = "./scans"


@dataclass
class ScanResult:
    """Results of a completed penetration test."""

    scan_id: str
    target: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    agent_states: List[AgentState] = field(default_factory=list)
    approval_log: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None


class ScanOrchestrator:
    """
    Central orchestrator for managing multi-agent penetration tests.

    Responsibilities:
    - Initialize and configure agent teams
    - Distribute tasks based on agent capabilities
    - Enforce human-in-the-loop approval workflow
    - Maintain shared context and discovery database
    - Coordinate inter-agent communication
    - Persist scan state for recovery
    - Aggregate findings and generate reports
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.scan_id = str(uuid.uuid4())
        self.status = ScanStatus.PENDING
        self.agents: Dict[str, BaseAgent] = {}
        self.message_bus = MessageBus()
        self.task_queue = TaskQueue()
        self.knowledge_base = KnowledgeBase()
        self.approval_gateway = ApprovalGateway(
            mode=config.approval_mode,
            audit_log_path=Path(config.save_dir) / "approval_audit.jsonl",
        )
        self.shared_context: Dict[str, Any] = {
            "target": config.target,
            "targets": [config.target],
            "scope": config.scope,
            "excluded": config.excluded,
            "discovered_services": [],
            "vulnerabilities": [],
            "credentials": [],
            "attack_paths": [],
        }
        self.findings: List[Dict[str, Any]] = []
        self.approval_log: List[Dict[str, Any]] = []
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.save_dir = Path(config.save_dir) / self.scan_id
        self._stop_requested = False

    def register_agent(self, agent: BaseAgent):
        """Register an agent with the orchestrator."""
        agent.approval_gateway = self.approval_gateway
        agent.message_bus = self.message_bus
        agent.knowledge_base = self.knowledge_base
        self.agents[agent.id] = agent
        asyncio.create_task(self.message_bus.register(agent.id)) if self._loop_running() else None

    def unregister_agent(self, agent_id: str):
        """Remove an agent from the orchestrator."""
        if agent_id in self.agents:
            del self.agents[agent_id]

    @staticmethod
    def _loop_running() -> bool:
        try:
            asyncio.get_running_loop()
            return True
        except RuntimeError:
            return False

    async def start(self):
        """Start the penetration test scan."""
        if self.status not in {ScanStatus.PENDING, ScanStatus.PAUSED}:
            raise RuntimeError(f"Cannot start scan from status {self.status.value}")
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()
        for agent in self.agents.values():
            await self.message_bus.register(agent.id)

        # Create save directory
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # Save initial state
        await self._save_state()

        # Register approval callback to log all requests
        self.approval_gateway.register_callback("logger", self._log_approval_request)

        print(f"[Orchestrator] Scan {self.scan_id} started for target: {self.config.target}")

    async def _log_approval_request(self, request):
        """Log all approval requests for audit trail."""
        self.approval_log.append(
            {"timestamp": datetime.utcnow().isoformat(), "request": request.to_dict()}
        )
        await self._save_state()

    async def execute_scan(self):
        """
        Execute the full penetration test with all registered agents.

        Coordinates agents in phases:
        1. Reconnaissance (passive and active)
        2. Vulnerability identification
        3. Exploitation (with approval)
        4. Post-exploitation (with approval)
        5. Reporting
        """
        if not self.agents:
            raise ValueError("No agents registered for scan")
        if self.status == ScanStatus.PENDING:
            await self.start()

        try:
            if self.approval_gateway.emergency_stop_active:
                self.status = ScanStatus.CANCELLED
                return
            # Phase 1: Reconnaissance
            recon_agents = [
                a for a in self.agents.values() if "reconnaissance" in a.get_capabilities()
            ]
            if recon_agents:
                print("[Orchestrator] Starting reconnaissance phase...")
                await self._execute_phase(recon_agents, "reconnaissance")

            # Phase 2: Vulnerability scanning
            vuln_agents = [
                a for a in self.agents.values() if "vulnerability_scanning" in a.get_capabilities()
            ]
            if vuln_agents:
                print("[Orchestrator] Starting vulnerability scanning phase...")
                await self._execute_phase(vuln_agents, "vulnerability_scanning")

            # Phase 3: Exploitation (requires approvals)
            exploit_agents = [
                a for a in self.agents.values() if "exploitation" in a.get_capabilities()
            ]
            if exploit_agents:
                print("[Orchestrator] Starting exploitation phase (awaiting approvals)...")
                await self._execute_phase(exploit_agents, "exploitation")

            # Phase 4: Post-exploitation (requires approvals)
            post_exploit_agents = [
                a for a in self.agents.values() if "post_exploitation" in a.get_capabilities()
            ]
            if post_exploit_agents:
                print("[Orchestrator] Starting post-exploitation phase (awaiting approvals)...")
                await self._execute_phase(post_exploit_agents, "post_exploitation")

            self.status = ScanStatus.COMPLETED
            self.completed_at = datetime.utcnow()
            print(f"[Orchestrator] Scan completed. Found {len(self.findings)} vulnerabilities.")

        except Exception as e:
            self.status = ScanStatus.ERROR
            self.completed_at = datetime.utcnow()
            print(f"[Orchestrator] Scan failed with error: {e}")
            raise
        finally:
            await self._save_state()
            await self._save_findings()

    async def _execute_phase(self, agents: List[BaseAgent], phase_name: str):
        """Execute a phase with multiple agents in parallel."""
        tasks = []
        for agent in agents:
            if agent.should_stop():
                continue

            queued_task = AgentTask(
                name=phase_name,
                required_capability=phase_name,
                context=self.shared_context,
                assigned_agent=agent.id,
            )
            await self.task_queue.put(queued_task)
            task = asyncio.create_task(agent.execute(phase_name, self.shared_context))
            tasks.append((queued_task, task))

        if tasks:
            results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)

            # Process results and update shared context
            for (queued_task, _), result in zip(tasks, results):
                if isinstance(result, Exception):
                    self.task_queue.complete(queued_task, str(result))
                    print(f"[Orchestrator] Agent execution error: {result}")
                    continue

                self.task_queue.complete(queued_task)

                if isinstance(result, dict):
                    # Merge findings
                    new_findings = result.get("findings", [])
                    for finding in new_findings:
                        self.findings.append(finding)
                    self.shared_context["findings"] = list(self.findings)

                    # Update shared context
                    if "context_updates" in result:
                        self.shared_context.update(result["context_updates"])
                        await self.knowledge_base.update(result["context_updates"])

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to the global collection."""
        finding["scan_id"] = self.scan_id
        finding["timestamp"] = datetime.utcnow().isoformat()
        self.findings.append(finding)

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Return all findings from all agents."""
        all_findings = self.findings.copy()
        for agent in self.agents.values():
            all_findings.extend(agent.get_findings())
        return all_findings

    async def pause(self):
        """Pause the scan by parking all active agents."""
        for agent in self.agents.values():
            if agent.status == AgentStatus.RUNNING:
                agent.park()
        self.status = ScanStatus.PAUSED
        await self._save_state()
        print("[Orchestrator] Scan paused")

    async def resume(self):
        """Resume a paused scan."""
        if self.status != ScanStatus.PAUSED:
            return
        for agent in self.agents.values():
            if agent.status == AgentStatus.PARKED:
                agent.resume()
        self.status = ScanStatus.RUNNING
        print("[Orchestrator] Scan resumed")

    async def stop(self):
        """Stop the scan gracefully."""
        self._stop_requested = True
        await self.approval_gateway.emergency_stop("scan stopped by operator")
        for agent in self.agents.values():
            agent.stop()
            await agent.cleanup()
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.utcnow()
        await self._save_state()
        print("[Orchestrator] Scan stopped")

    async def _save_state(self):
        """Persist current scan state to disk."""
        state = {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "config": {
                "target": self.config.target,
                "scope": self.config.scope,
                "excluded": self.config.excluded,
                "approval_mode": self.config.approval_mode,
            },
            "shared_context": self.shared_context,
            "agent_count": len(self.agents),
            "finding_count": len(self.findings),
            "approval_log": self.approval_log,
            "knowledge_base": await self.knowledge_base.snapshot(),
            "task_queue": self.task_queue.snapshot(),
            "agent_states": [self._agent_state_dict(agent) for agent in self.agents.values()],
        }

        state_file = self.save_dir / "scan_state.json"
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)

    async def _save_findings(self):
        """Save all findings to disk in multiple formats."""
        all_findings = self.get_all_findings()

        # JSON format
        findings_file = self.save_dir / "findings.json"
        findings_file.write_text(to_json(all_findings))
        (self.save_dir / "findings.csv").write_text(to_csv(all_findings))
        (self.save_dir / "findings.sarif").write_text(to_sarif(all_findings))

        # Markdown report
        md_report = self._generate_markdown_report()
        md_file = self.save_dir / "report.md"
        with open(md_file, "w") as f:
            f.write(md_report)

    def _generate_markdown_report(self) -> str:
        """Generate a Markdown report from findings."""
        lines = [
            "# NetworkForgeAI Penetration Test Report",
            "",
            f"**Scan ID:** {self.scan_id}",
            f"**Target:** {self.config.target}",
            f"**Started:** {self.started_at.isoformat() if self.started_at else 'N/A'}",
            f"**Completed:** {self.completed_at.isoformat() if self.completed_at else 'In Progress'}",
            f"**Status:** {self.status.value}",
            "",
            "## Executive Summary",
            "",
            f"Total findings: {len(self.findings)}",
            "",
        ]

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            sev = finding.get("severity", "Unknown")
            by_severity.setdefault(sev, []).append(finding)

        for severity, findings in sorted(by_severity.items()):
            lines.append(f"### {severity}: {len(findings)}")

        lines.extend(["", "## Detailed Findings", ""])

        for i, finding in enumerate(self.findings, 1):
            lines.extend(
                [
                    f"### Finding {i}: {finding.get('title', 'Untitled')}",
                    "",
                    f"**Severity:** {finding.get('severity', 'Unknown')}",
                    f"**Category:** {finding.get('category', 'Unknown')}",
                    f"**Target:** {finding.get('target', 'Unknown')}",
                    "",
                    "**Description:**",
                    finding.get("description", "No description"),
                    "",
                    "**Proof of Concept:**",
                    "```",
                    finding.get("poc", "No PoC available"),
                    "```",
                    "",
                    "**Reproduction Steps:**",
                    finding.get("reproduction_steps", "No steps provided"),
                    "",
                    "**Remediation:**",
                    finding.get("remediation", "No remediation guidance"),
                    "",
                    "---",
                    "",
                ]
            )

        return "\n".join(lines)

    @staticmethod
    def _agent_state_dict(agent: BaseAgent) -> Dict[str, Any]:
        state = agent.to_state()
        return {
            "id": state.id,
            "name": state.name,
            "status": state.status.value,
            "current_task": state.current_task,
            "findings": state.findings,
            "created_at": state.created_at.isoformat(),
            "last_active": state.last_active.isoformat(),
            "context_summary": state.context_summary,
        }

    @classmethod
    async def from_state(cls, scan_id: str, save_base_dir: str = "./scans") -> "ScanOrchestrator":
        """Restore a scan from persisted state."""
        save_dir = Path(save_base_dir) / scan_id
        state_file = save_dir / "scan_state.json"

        if not state_file.exists():
            raise FileNotFoundError(f"No saved state found for scan {scan_id}")

        with open(state_file) as f:
            state = json.load(f)

        # Reconstruct config
        config = ScanConfig(
            target=state["config"]["target"],
            scope=state["config"]["scope"],
            excluded=state["config"]["excluded"],
            approval_mode=state["config"]["approval_mode"],
            save_dir=save_base_dir,
        )

        orchestrator = cls(config)
        orchestrator.scan_id = scan_id
        orchestrator.status = ScanStatus(state["status"])
        orchestrator.started_at = (
            datetime.fromisoformat(state["started_at"]) if state["started_at"] else None
        )
        orchestrator.completed_at = (
            datetime.fromisoformat(state["completed_at"]) if state["completed_at"] else None
        )
        orchestrator.shared_context = state["shared_context"]
        orchestrator.approval_log = state["approval_log"]
        await orchestrator.knowledge_base.restore(state.get("knowledge_base", {}))

        findings_file = save_dir / "findings.json"
        if findings_file.exists():
            with open(findings_file) as f:
                orchestrator.findings = json.load(f)

        return orchestrator
