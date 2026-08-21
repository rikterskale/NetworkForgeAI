"""In-process asynchronous agent message bus."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AgentMessage:
    sender_id: str
    recipient_id: str
    payload: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class MessageBus:
    def __init__(self) -> None:
        self._mailboxes: dict[str, asyncio.Queue[AgentMessage]] = {}
        self._lock = asyncio.Lock()

    async def register(self, agent_id: str) -> asyncio.Queue[AgentMessage]:
        async with self._lock:
            return self._mailboxes.setdefault(agent_id, asyncio.Queue())

    async def unregister(self, agent_id: str) -> None:
        async with self._lock:
            self._mailboxes.pop(agent_id, None)

    async def send(self, message: AgentMessage) -> bool:
        async with self._lock:
            mailbox = self._mailboxes.get(message.recipient_id)
        if mailbox is None:
            return False
        await mailbox.put(message)
        return True

    async def receive(self, agent_id: str, timeout: float = 0) -> AgentMessage | None:
        async with self._lock:
            mailbox = self._mailboxes.get(agent_id)
        if mailbox is None:
            return None
        try:
            if timeout > 0:
                return await asyncio.wait_for(mailbox.get(), timeout)
            return mailbox.get_nowait()
        except (asyncio.TimeoutError, asyncio.QueueEmpty):
            return None
