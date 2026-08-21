"""
NetworkForgeAI Core Package
Central orchestration and agent management with human-in-the-loop controls.
"""

__version__ = "0.1.0"
__author__ = "NetworkForgeAI Team"
from .knowledge_base import KnowledgeBase
from .message_bus import AgentMessage, MessageBus
from .scope import ScopePolicy
from .task_queue import AgentTask, TaskQueue, TaskStatus

__all__ = [
    "KnowledgeBase",
    "AgentMessage",
    "MessageBus",
    "ScopePolicy",
    "AgentTask",
    "TaskQueue",
    "TaskStatus",
]
