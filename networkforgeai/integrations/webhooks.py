"""Minimal, explicit webhook boundary for CI and collaboration integrations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class WebhookEvent:
    event_type: str
    summary: str
    payload: dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "summary": self.summary,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def findings_gate(cls, passed: bool, blocking_count: int) -> "WebhookEvent":
        status = "passed" if passed else "blocked"
        return cls(
            "findings_gate",
            f"CI findings gate {status}",
            {"passed": passed, "blocking_count": blocking_count},
        )


class WebhookNotifier:
    """Send JSON events only to explicit HTTPS endpoints."""

    def __init__(self, endpoint: str, timeout: float = 10.0, allow_http: bool = False):
        if not endpoint.startswith("https://") and not (
            allow_http and endpoint.startswith("http://")
        ):
            raise ValueError("Webhook endpoint must use HTTPS")
        self.endpoint = endpoint
        self.timeout = timeout

    def send(self, event: WebhookEvent) -> int:
        request = Request(
            self.endpoint,
            data=json.dumps(event.to_dict()).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:  # nosec B310 - endpoint scheme validated in __init__
            return int(response.status)
