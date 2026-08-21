"""Interactive CLI surfaces: approval prompts and live agent status display.

Both components fail closed: if no interactive terminal is available, approval
prompts reject the request instead of allowing it.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import IO

from ..core.approval_gateway import ApprovalGateway, ApprovalRequest, ApprovalStatus


class ApprovalPrompt:
    """Terminal approval prompt registered as an approval-gateway callback.

    On each state change the request is rendered; pending requests are put to a
    human via stdin. Any input failure rejects the request (fail closed).
    """

    def __init__(
        self, gateway: ApprovalGateway, stream: IO[str] | None = None, interactive: bool | None = None
    ):
        self.gateway = gateway
        self.stream = stream or sys.stdout
        self.interactive = sys.stdin.isatty() if interactive is None else interactive

    async def __call__(self, request: ApprovalRequest) -> None:
        self._render(request)
        if request.status is not ApprovalStatus.PENDING or not self.interactive:
            return
        try:
            answer = input(
                f"Approve action {request.id[:8]}? [y=approve / n=reject / anything else=reject] "
            )
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer.strip().lower() in {"y", "yes"}:
            await self.gateway.approve(request.id, "cli_operator")
        else:
            await self.gateway.reject(request.id, "cli_operator", "rejected at terminal prompt")

    def _render(self, request: ApprovalRequest) -> None:
        print(file=self.stream)
        print(
            f"[{datetime.utcnow().isoformat(timespec='seconds')}Z] Approval request {request.id}",
            file=self.stream,
        )
        print(f"  Action : {request.action_type}", file=self.stream)
        print(f"  Target : {request.target}", file=self.stream)
        print(f"  Risk   : {request.risk_level.value.upper()}", file=self.stream)
        print(f"  Detail : {request.description}", file=self.stream)
        if not self.interactive and request.status is ApprovalStatus.PENDING:
            print(
                "  Non-interactive session: request remains PENDING (fail closed).",
                file=self.stream,
            )


class StatusDisplay:
    """Minimal dependency-free live status table for registered agents."""

    def __init__(self, stream: IO[str] | None = None):
        self.stream = stream or sys.stdout
        self._statuses: dict[str, str] = {}
        self._events: list[tuple[str, str]] = []

    def update(self, agent_id: str, status: str) -> None:
        previous = self._statuses.get(agent_id)
        self._statuses[agent_id] = status
        if previous != status:
            self._events.append((agent_id, status))
            print(f"[status] {agent_id}: {previous or 'unknown'} -> {status}", file=self.stream)

    @property
    def events(self) -> list[tuple[str, str]]:
        return list(self._events)

    def render(self) -> str:
        width = max((len(agent) for agent in self._statuses), default=0)
        lines = [
            f"{agent.ljust(width)}  {status}" for agent, status in sorted(self._statuses.items())
        ]
        return "\n".join(lines)
