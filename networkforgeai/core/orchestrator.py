"""
Scan Orchestrator - Central coordinator for multi-agent penetration tests

Manages agent lifecycle, coordinates task distribution, enforces approval workflows,
and maintains shared context across all agents in a scan session.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..observability import bind_log_context
from ..reporting import to_csv, to_json, to_pdf, to_sarif
from .approval_gateway import ApprovalGateway, _as_utc
from .base_agent import AgentState, AgentStatus, BaseAgent
from .knowledge_base import KnowledgeBase
from .message_bus import MessageBus
from .task_queue import AgentTask, TaskQueue

logger = logging.getLogger(__name__)


def _format_poc(poc: Any) -> str:
    """Render a PoC that may be a plain string or an enriched ``{commands: [...]}``."""
    if isinstance(poc, dict):
        commands = poc.get("commands") or []
        return "\n".join(str(command) for command in commands) or "No PoC available"
    return str(poc) if poc else "No PoC available"


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    PARTIAL = "partial"
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
        self._phase_errors: list[dict[str, str]] = []
        self._phase_semaphore = asyncio.Semaphore(max(1, config.max_agents))

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent with the orchestrator."""
        agent.approval_gateway = self.approval_gateway
        agent.message_bus = self.message_bus
        agent.knowledge_base = self.knowledge_base
        self.agents[agent.id] = agent
        asyncio.create_task(self.message_bus.register(agent.id)) if self._loop_running() else None

    def unregister_agent(self, agent_id: str) -> None:
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

    async def start(self) -> None:
        """Start the penetration test scan."""
        if self.status not in {ScanStatus.PENDING, ScanStatus.PAUSED}:
            raise RuntimeError(f"Cannot start scan from status {self.status.value}")
        self.status = ScanStatus.RUNNING
        bind_log_context(scan_id=self.scan_id)
        self.started_at = datetime.now(timezone.utc)
        for agent in self.agents.values():
            await self.message_bus.register(agent.id)

        # Create save directory
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # Save initial state
        await self._save_state()

        # Register approval callback to log all requests
        self.approval_gateway.register_callback("logger", self._log_approval_request)

        logger.info("Scan %s started for target: %s", self.scan_id, self.config.target)

    async def _log_approval_request(self, request: Any) -> None:
        """Log all approval requests for audit trail."""
        self.approval_log.append(
            {"timestamp": datetime.now(timezone.utc).isoformat(), "request": request.to_dict()}
        )
        await self._save_state()

    async def execute_scan(self) -> None:
        """
        Execute the full penetration test with all registered agents.

        Coordinates agents in phases:
        1. Reconnaissance (passive and active)
        2. Vulnerability identification
        3. Attack path planning
        4. Exploitation (with approval)
        5. Post-exploitation (with approval)
        6. Quality assurance on findings
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
                logger.info("Starting reconnaissance phase")
                await self._execute_phase(recon_agents, "reconnaissance")

            # Phase 2: Vulnerability scanning
            vuln_agents = [
                a for a in self.agents.values() if "vulnerability_scanning" in a.get_capabilities()
            ]
            if vuln_agents:
                logger.info("Starting vulnerability scanning phase")
                await self._execute_phase(vuln_agents, "vulnerability_scanning")

            # Phase 2.5: Attack path planning (prioritized, approval-gated)
            planning_agents = [
                a for a in self.agents.values() if "attack_path_planning" in a.get_capabilities()
            ]
            if planning_agents:
                logger.info("Starting attack path planning phase")
                self.shared_context["vulnerabilities"] = list(self.findings)
                await self._execute_phase(planning_agents, "attack_path_planning")

            # Phase 3: Exploitation (requires approvals)
            exploit_agents = [
                a for a in self.agents.values() if "exploitation" in a.get_capabilities()
            ]
            if exploit_agents:
                logger.info("Starting exploitation phase (awaiting approvals)")
                await self._execute_phase(exploit_agents, "exploitation")

            # Phase 4: Post-exploitation (requires approvals)
            post_exploit_agents = [
                a for a in self.agents.values() if "post_exploitation" in a.get_capabilities()
            ]
            if post_exploit_agents:
                logger.info("Starting post-exploitation phase (awaiting approvals)")
                await self._execute_phase(post_exploit_agents, "post_exploitation")

            # Phase 4.5: Quality assurance (deduplicate and validate findings)
            qa_agents = [
                a for a in self.agents.values() if "quality_assurance" in a.get_capabilities()
            ]
            if qa_agents and self.findings:
                logger.info("Running quality assurance on findings")
                self.shared_context["findings"] = list(self.findings)
                await self._execute_phase(qa_agents, "quality_assurance")
                deduplicated = self.shared_context.get("deduplicated_findings")
                if isinstance(deduplicated, list):
                    self.findings = list(deduplicated)
                    self.shared_context["findings"] = list(self.findings)

            self.status = ScanStatus.PARTIAL if self._phase_errors else ScanStatus.COMPLETED
            self.completed_at = datetime.now(timezone.utc)
            logger.info(
                "Scan %s finished with status %s. Found %d findings and %d phase errors.",
                self.scan_id,
                self.status.value,
                len(self.findings),
                len(self._phase_errors),
            )

        except Exception as e:
            self.status = ScanStatus.ERROR
            self.completed_at = datetime.now(timezone.utc)
            logger.error("Scan failed with error: %s", e)
            raise
        finally:
            await self._save_state()
            await self._save_findings()

    async def _execute_phase(self, agents: list[BaseAgent], phase_name: str) -> None:
        """Execute a phase with multiple agents in parallel."""
        bind_log_context(scan_id=self.scan_id)
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

            async def run_limited(current_agent: BaseAgent = agent) -> Any:
                bind_log_context(scan_id=self.scan_id, agent_id=current_agent.id)
                async with self._phase_semaphore:
                    return await current_agent.execute(phase_name, self.shared_context)

            task = asyncio.create_task(run_limited())
            tasks.append((queued_task, task))

        if tasks:
            results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)

            # Process results and update shared context
            for (queued_task, _), result in zip(tasks, results):
                if isinstance(result, Exception):
                    self.task_queue.complete(queued_task, str(result))
                    error = {
                        "phase": phase_name,
                        "agent_id": queued_task.assigned_agent or "",
                        "error": str(result),
                    }
                    self._phase_errors.append(error)
                    self.shared_context.setdefault("phase_errors", []).append(error)
                    logger.error(
                        "Agent execution error scan_id=%s phase=%s agent_id=%s: %s",
                        self.scan_id,
                        phase_name,
                        queued_task.assigned_agent,
                        result,
                    )
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

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a finding to the global collection."""
        finding["scan_id"] = self.scan_id
        finding["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.findings.append(finding)

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Return all findings from all agents."""
        all_findings = self.findings.copy()
        for agent in self.agents.values():
            all_findings.extend(agent.get_findings())
        return all_findings

    async def pause(self) -> None:
        """Pause the scan by parking all active agents."""
        for agent in self.agents.values():
            if agent.status == AgentStatus.RUNNING:
                agent.park()
        self.status = ScanStatus.PAUSED
        await self._save_state()
        logger.info("Scan paused")

    async def resume(self) -> None:
        """Resume a paused scan."""
        if self.status != ScanStatus.PAUSED:
            return
        for agent in self.agents.values():
            if agent.status == AgentStatus.PARKED:
                agent.resume()
        self.status = ScanStatus.RUNNING
        logger.info("Scan resumed")

    async def stop(self) -> None:
        """Stop the scan gracefully."""
        self._stop_requested = True
        await self.approval_gateway.emergency_stop("scan stopped by operator")
        for agent in self.agents.values():
            agent.stop()
            await agent.cleanup()
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)
        await self._save_state()
        logger.info("Scan stopped")

    async def _save_state(self) -> None:
        """Persist current scan state to disk."""
        state: dict[str, Any] = {
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
            "approval_requests": self.approval_gateway.snapshot(),
            "phase_errors": self._phase_errors,
            "knowledge_base": await self.knowledge_base.snapshot(),
            "task_queue": self.task_queue.snapshot(),
            "agent_states": [self._agent_state_dict(agent) for agent in self.agents.values()],
        }

        state_file = self.save_dir / "scan_state.json"
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

    async def _save_findings(self) -> None:
        """Save all findings to disk in multiple formats."""
        all_findings = self.get_all_findings()

        # JSON format
        findings_file = self.save_dir / "findings.json"
        findings_file.write_text(to_json(all_findings))
        (self.save_dir / "findings.csv").write_text(to_csv(all_findings))
        (self.save_dir / "findings.sarif").write_text(to_sarif(all_findings))
        (self.save_dir / "executive-summary.pdf").write_bytes(to_pdf(all_findings))

        # Markdown report
        md_report = self._generate_markdown_report()
        md_file = self.save_dir / "report.md"
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_report)

    def _generate_markdown_report(self) -> str:
        """Generate a vendor-grade Markdown report from findings.

        Uses the enrichment pass output (CVSS, ATT&CK, correlated attack paths)
        when the PlanningAgent has populated it in shared context; otherwise it
        summarizes the raw findings without fabricating correlation data.
        """
        from ..reporting.narrative import (
            attack_coverage_section,
            attack_path_section,
            executive_summary,
        )

        enriched = self.shared_context.get("enriched_findings") or []
        report_findings = enriched if enriched else self.findings
        attack_paths = self.shared_context.get("attack_paths") or []

        lines = [
            "# NetworkForgeAI Penetration Test Report",
            "",
            f"**Scan ID:** {self.scan_id}",
            f"**Target:** {self.config.target}",
            f"**Started:** {self.started_at.isoformat() if self.started_at else 'N/A'}",
            f"**Completed:** {self.completed_at.isoformat() if self.completed_at else 'In Progress'}",
            f"**Status:** {self.status.value}",
            "",
        ]
        lines.extend(executive_summary(report_findings, target=self.config.target))
        lines.extend(attack_coverage_section(report_findings))
        lines.extend(attack_path_section(attack_paths))

        lines.extend(["## Detailed Findings", ""])

        for i, finding in enumerate(report_findings, 1):
            severity = finding.get("adjusted_severity") or finding.get("severity", "Unknown")
            cvss = finding.get("adjusted_cvss") or finding.get("cvss_score")
            techniques = ", ".join(
                f"{t.get('id')} {t.get('name')}" for t in finding.get("attack_techniques", [])
            )
            lines.extend(
                [
                    f"### Finding {i}: {finding.get('title', 'Untitled')}",
                    "",
                    f"**Severity:** {severity}" + (f" (CVSS {cvss})" if cvss else ""),
                    f"**Target:** {finding.get('target', 'Unknown')}",
                ]
            )
            if techniques:
                lines.append(f"**ATT&CK:** {techniques}")
            lines.extend(
                [
                    "",
                    "**Description:**",
                    finding.get("description", "No description"),
                    "",
                    "**Proof of Concept:**",
                    "```",
                    _format_poc(finding.get("poc")),
                    "```",
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
            _as_utc(datetime.fromisoformat(state["started_at"])) if state["started_at"] else None
        )
        orchestrator.completed_at = (
            _as_utc(datetime.fromisoformat(state["completed_at"]))
            if state["completed_at"]
            else None
        )
        orchestrator.shared_context = state["shared_context"]
        orchestrator.approval_log = state["approval_log"]
        orchestrator._phase_errors = list(state.get("phase_errors", []))
        orchestrator.approval_gateway.restore(state.get("approval_requests", []))
        await orchestrator.knowledge_base.restore(state.get("knowledge_base", {}))

        findings_file = save_dir / "findings.json"
        if findings_file.exists():
            with open(findings_file) as f:
                orchestrator.findings = json.load(f)

        return orchestrator
