"""
NetworkForgeAI Core Package
Central orchestration and agent management with human-in-the-loop controls.
"""

__version__ = "0.1.0"
__author__ = "NetworkForgeAI Team"
from .debate import DebateOpinion, DebateResult, MultiAgentDebate
from .knowledge_base import KnowledgeBase
from .message_bus import AgentMessage, MessageBus
from .retrieval import HybridRetriever, LocalRetriever, RetrievalDocument, RetrievalResult
from .scope import ScopePolicy
from .task_queue import AgentTask, TaskQueue, TaskStatus

__all__ = [
    "KnowledgeBase",
    "DebateOpinion",
    "DebateResult",
    "MultiAgentDebate",
    "LocalRetriever",
    "HybridRetriever",
    "RetrievalDocument",
    "RetrievalResult",
    "AgentMessage",
    "MessageBus",
    "ScopePolicy",
    "AgentTask",
    "TaskQueue",
    "TaskStatus",
]
