"""Capability-aware task queue used by the scan orchestrator."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AgentTask:
    name: str
    required_capability: str
    context: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: str | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


class TaskQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[AgentTask] = asyncio.Queue()
        self._tasks: dict[str, AgentTask] = {}

    async def put(self, task: AgentTask) -> None:
        if not task.id:
            import uuid
            task.id = str(uuid.uuid4())
        self._tasks[task.id] = task
        await self._queue.put(task)

    async def get(self) -> AgentTask:
        task = await self._queue.get()
        task.status = TaskStatus.RUNNING
        return task

    def complete(self, task: AgentTask, error: str | None = None) -> None:
        task.status = TaskStatus.FAILED if error else TaskStatus.COMPLETED
        task.error = error

    def snapshot(self) -> list[dict[str, Any]]:
        return [{**task.__dict__, "status": task.status.value,
                 "created_at": task.created_at.isoformat()} for task in self._tasks.values()]

