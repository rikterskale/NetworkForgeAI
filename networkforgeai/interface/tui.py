"""Terminal UI components (TUI-001..004).

Dependency-free Rich-style terminal surfaces built on ANSI escape codes:
progress/table rendering, color-coded log streaming, an interactive menu,
and an approval dialog. Like :mod:`cli_ui`, the approval dialog fails
closed when no interactive terminal is available.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import IO, Callable, Dict, List, Optional, Sequence

from ..core.approval_gateway import ApprovalGateway, ApprovalRequest, ApprovalStatus

_RESET = "\033[0m"
_COLORS = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}
_BAR_WIDTH = 24


class TUIDisplay:
    """Progress bar and table rendering for agent/scan state (TUI-001)."""

    def __init__(self, stream: IO[str] | None = None, colors: bool | None = None):
        self.stream = stream or sys.stdout
        self._colors = self._detect_colors() if colors is None else colors

    def _detect_colors(self) -> bool:
        return bool(getattr(self.stream, "isatty", lambda: False)())

    def _paint(self, text: str, color: str) -> str:
        if not self._colors:
            return text
        return f"{_COLORS.get(color, '')}{text}{_RESET}"

    def progress(self, done: int, total: int, label: str = "tasks") -> str:
        """Render a one-line progress bar."""
        ratio = 0 if total <= 0 else max(0.0, min(1.0, done / total))
        filled = round(ratio * _BAR_WIDTH)
        bar = "#" * filled + "-" * (_BAR_WIDTH - filled)
        percent = int(round(ratio * 100))
        return f"[{bar}] {percent:3d}% {done}/{total} {label}"

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
        """Render a plain-text aligned table with colored header."""
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        header_line = "  ".join(
            self._paint(h.ljust(widths[i]), "cyan") for i, h in enumerate(headers)
        )
        divider = "  ".join("-" * w for w in widths)
        body = ["  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)) for row in rows]
        return "\n".join([header_line, divider, *body])

    def show(self, text: str) -> None:
        print(text, file=self.stream)


class LogStreamPanel:
    """Color-coded live log stream for agent events (TUI-002)."""

    LEVEL_MARKERS: Dict[str, tuple[str, str]] = {
        "error": ("ERROR", "red"),
        "warning": ("WARN", "yellow"),
        "approval": ("APPROVAL", "cyan"),
    }

    def __init__(self, stream: IO[str] | None = None, colors: bool | None = None):
        self.stream = stream or sys.stdout
        self._colors = (
            bool(getattr(self.stream, "isatty", lambda: False)()) if colors is None else colors
        )
        self.entries: List[tuple[str, str, str]] = []

    def log(self, source: str, message: str) -> str:
        """Record and emit a log line; returns the rendered line."""
        lowered = message.lower()
        tag, color = next(
            ((t, c) for marker, (t, c) in self.LEVEL_MARKERS.items() if marker in lowered),
            ("INFO", "grey"),
        )
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        line = f"{timestamp} [{tag}] {source}: {message}"
        if self._colors:
            line = f"{_COLORS.get(color, '')}{line}{_RESET}"
        self.entries.append((source, tag, message))
        print(line, file=self.stream)
        return line


class InteractiveMenu:
    """Number-key navigated terminal menu (TUI-003).

    Returns the selected item's value, or ``None`` when the session is not
    interactive or input fails (fail closed).
    """

    def __init__(
        self,
        title: str,
        items: Sequence[tuple[str, Callable[[], object] | None]],
        instream: IO[str] | None = None,
        outstream: IO[str] | None = None,
        interactive: bool | None = None,
    ):
        self.title = title
        self.items = list(items)
        self.instream = instream or sys.stdin
        self.outstream = outstream or sys.stdout
        self.interactive = self.instream.isatty() if interactive is None else interactive

    def render(self) -> str:
        lines = [self.title]
        for index, (label, _) in enumerate(self.items, 1):
            lines.append(f"  {index}) {label}")
        lines.append("  q) quit")
        return "\n".join(lines)

    def run(self) -> Optional[object]:
        if not self.interactive or not self.items:
            print(file=self.outstream)
            print(self.render(), file=self.outstream)
            print("Non-interactive session: menu disabled.", file=self.outstream)
            return None
        while True:
            print(self.render(), file=self.outstream)
            print(f"{self.title} - select> ", file=self.outstream, end="", flush=True)
            try:
                choice = self.instream.readline().strip().lower()
            except (EOFError, KeyboardInterrupt, OSError):
                return None
            if choice in {"q", ""}:
                return None
            if choice.isdigit() and 1 <= int(choice) <= len(self.items):
                _, action = self.items[int(choice) - 1]
                return action() if callable(action) else None


class ApprovalDialog:
    """Boxed approval dialog registered as an approval-gateway callback (TUI-004).

    Fail closed: any input error rejects the request; non-interactive
    sessions leave the request PENDING.
    """

    def __init__(
        self,
        gateway: ApprovalGateway,
        stream: IO[str] | None = None,
        interactive: bool | None = None,
        operator: str = "tui_operator",
    ):
        self.gateway = gateway
        self.stream = stream or sys.stdout
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self.operator = operator

    async def __call__(self, request: ApprovalRequest) -> None:
        print(self.render(request), file=self.stream)
        if request.status is not ApprovalStatus.PENDING or not self.interactive:
            return
        try:
            answer = input(f"Approve {request.id[:8]}? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer.strip().lower() in {"y", "yes"}:
            await self.gateway.approve(request.id, self.operator)
        else:
            await self.gateway.reject(request.id, self.operator, "rejected at TUI dialog")

    def render(self, request: ApprovalRequest) -> str:
        width = 62
        rows = [
            f"Approval request {request.id}",
            f"Action : {request.action_type}",
            f"Target : {request.target}",
            f"Risk   : {request.risk_level.value.upper()}",
            f"Detail : {request.description}",
        ]
        border = "+" + "-" * width + "+"
        lines = [border]
        for row in rows:
            lines.append("| " + row.ljust(width - 2)[: width - 2] + " |")
        lines.append(border)
        if not self.interactive and request.status is ApprovalStatus.PENDING:
            lines.append("| Non-interactive: request stays PENDING." + " " * (width - 41) + "|")
            lines.append(border)
        return "\n".join(lines)
