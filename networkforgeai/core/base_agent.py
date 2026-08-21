"""
Base Agent Class - Foundation for all specialized pentesting agents

All agents must inherit from this base class and implement required methods.
Agents cannot execute high-risk actions without approval through the gateway.
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .approval_gateway import ApprovalGateway, ApprovalStatus, RiskLevel
from .knowledge_base import KnowledgeBase
from .message_bus import AgentMessage, MessageBus


class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    PARKED = "parked"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class AgentState:
    """Snapshot of agent state for persistence and recovery."""

    id: str
    name: str
    status: AgentStatus
    current_task: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_active: datetime = field(default_factory=datetime.utcnow)
    context_summary: str = ""


class BaseAgent(ABC):
    """
    Abstract base class for all NetworkForgeAI agents.

    Provides:
    - Lifecycle management (start, stop, park, resume)
    - Approval gateway integration
    - Finding collection and reporting
    - State serialization for recovery
    - Inter-agent communication mailbox
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        name: Optional[str] = None,
        approval_gateway: Optional[ApprovalGateway] = None,
        message_bus: Optional[MessageBus] = None,
        model_adapter: Any = None,
        tool_registry: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        self.id = agent_id or str(uuid.uuid4())
        self.name = name or self.__class__.__name__
        self.approval_gateway = approval_gateway
        self.message_bus = message_bus
        self.model_adapter = model_adapter
        self.knowledge_base: Optional[KnowledgeBase] = kwargs.get("knowledge_base")
        self.tool_registry = tool_registry or {}
        self.status = AgentStatus.IDLE
        self.current_task: Optional[str] = None
        self.findings: List[Dict[str, Any]] = []
        self.mailbox: asyncio.Queue = asyncio.Queue()
        self._stop_requested = False
        self.created_at = datetime.utcnow()
        self.last_active = datetime.utcnow()
        self.context_summary = ""

    @abstractmethod
    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's primary function.

        Must be implemented by subclasses.

        Args:
            task: Task description from orchestrator
            context: Shared context including discoveries from other agents

        Returns:
            Dictionary with results, new_findings, and next_steps
        """
        pass

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """
        Return list of capabilities this agent provides.

        Example: ["subdomain_enumeration", "port_scanning", "sql_injection_testing"]
        """
        pass

    async def request_approval(
        self,
        action_type: str,
        description: str,
        target: str,
        risk_level: RiskLevel,
        details: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
    ) -> tuple[bool, Optional[Dict[str, Any]]]:
        """
        Request human approval for an action.

        Blocks until approval is granted, rejected, or expired.

        Returns:
            Tuple of (approved: bool, response_data: Optional[Dict])
        """
        if not self.approval_gateway:
            raise RuntimeError("Approval gateway not configured")

        self.status = AgentStatus.WAITING_APPROVAL

        request = await self.approval_gateway.request_approval(
            agent_id=self.id,
            action_type=action_type,
            description=description,
            target=target,
            risk_level=risk_level,
            details=details,
            timeout_seconds=timeout_seconds,
        )

        # Wait for decision
        final_request = await self.approval_gateway.wait_for_approval(request.id)

        self.last_active = datetime.utcnow()

        if final_request.status == ApprovalStatus.APPROVED:
            self.status = AgentStatus.RUNNING
            return True, final_request.response_data
        else:
            self.status = AgentStatus.IDLE
            return False, None

    def add_finding(self, finding: Dict[str, Any]):
        """Add a validated finding to the agent's collection."""
        finding["agent_id"] = self.id
        finding["agent_name"] = self.name
        finding["timestamp"] = datetime.utcnow().isoformat()
        self.findings.append(finding)
        self.last_active = datetime.utcnow()

    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings collected by this agent."""
        return self.findings.copy()

    async def send_message(self, recipient_id: str, message: Dict[str, Any]):
        """
        Send a message to another agent's mailbox.

        Used for inter-agent coordination and discovery sharing.
        """
        if self.message_bus is None:
            raise RuntimeError("Message bus not configured")
        delivered = await self.message_bus.send(
            AgentMessage(sender_id=self.id, recipient_id=recipient_id, payload=message)
        )
        if not delivered:
            raise ValueError(f"Recipient agent is not registered: {recipient_id}")

    async def receive_message(self, timeout: float = 0) -> Optional[Dict[str, Any]]:
        """
        Receive a message from the agent's mailbox.

        If timeout is 0, returns immediately (or None if empty).
        """
        try:
            if timeout > 0:
                if self.message_bus is not None:
                    message = await self.message_bus.receive(self.id, timeout)
                    return message.payload if message else None
                return await asyncio.wait_for(self.mailbox.get(), timeout=timeout)
            else:
                if self.message_bus is not None:
                    message = await self.message_bus.receive(self.id)
                    return message.payload if message else None
                return self.mailbox.get_nowait()
        except (asyncio.TimeoutError, asyncio.QueueEmpty):
            return None

    def park(self):
        """Park the agent (pause execution while preserving state)."""
        self.status = AgentStatus.PARKED
        self.context_summary = self._summarize_context()

    def resume(self):
        """Resume a parked agent."""
        if self.status == AgentStatus.PARKED:
            self.status = AgentStatus.IDLE

    def stop(self):
        """Request graceful stop of the agent."""
        self._stop_requested = True

    def should_stop(self) -> bool:
        """Check if stop has been requested."""
        return self._stop_requested

    async def ask_model(self, messages: List[Any], **kwargs):
        """Call the configured model adapter, if one is attached."""
        if self.model_adapter is None:
            raise RuntimeError("No model adapter configured for this agent")
        return await self.model_adapter.chat(messages, **kwargs)

    async def analyze_context(self, prompt: str, context: Dict[str, Any]) -> Any:
        """Run a model-backed analysis with retry and bounded context when configured."""
        from ..models.base_adapter import Message

        retrieved_context = ""
        if self.knowledge_base is not None:
            matches = await self.knowledge_base.retrieve(prompt, top_k=5, min_score=0.25)
            if matches:
                retrieved_context = "\nRetrieved knowledge:\n" + "\n".join(
                    f"- {match.document.text}" for match in matches
                )
        messages = [
            Message(role="user", content=f"{prompt}\nContext: {context}{retrieved_context}")
        ]
        if hasattr(self.model_adapter, "prepare_context"):
            messages = self.model_adapter.prepare_context(messages)
        if hasattr(self.model_adapter, "chat_with_retry"):
            response = await self.model_adapter.chat_with_retry(messages)
        else:
            response = await self.ask_model(messages)
        return response

    def get_tool(self, name: str) -> Any:
        if name not in self.tool_registry:
            raise KeyError(f"Tool is not registered for agent: {name}")
        return self.tool_registry[name]

    def _summarize_context(self) -> str:
        """Create a summary of current context for state persistence."""
        return f"Agent {self.name} has {len(self.findings)} findings. Status: {self.status.value}"

    def to_state(self) -> AgentState:
        """Serialize current state for persistence."""
        return AgentState(
            id=self.id,
            name=self.name,
            status=self.status,
            current_task=self.current_task,
            findings=self.findings,
            created_at=self.created_at,
            last_active=self.last_active,
            context_summary=self.context_summary,
        )

    def from_state(self, state: AgentState):
        """Restore state from serialized snapshot."""
        self.id = state.id
        self.name = state.name
        self.status = state.status
        self.current_task = state.current_task
        self.findings = state.findings
        self.created_at = state.created_at
        self.last_active = state.last_active
        self.context_summary = state.context_summary

    async def cleanup(self):
        """Cleanup resources before agent termination."""
        pass  # Override in subclasses if needed
