"""Central logging configuration.

The framework logs through the standard :mod:`logging` module. Call
:func:`configure_logging` once at process start (the CLI and dashboard do) so
the configured ``LOG_LEVEL`` is honored consistently. Library code must only
call ``logging.getLogger(__name__)`` and never configure handlers itself.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from threading import Lock
from typing import Any

_CONFIGURED = False
_LOG_CONTEXT: ContextVar[dict[str, str]] = ContextVar("networkforgeai_log_context", default={})
_METRICS: dict[str, float] = {}
_METRICS_LOCK = Lock()

_DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s scan_id=%(scan_id)s %(message)s"


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _LOG_CONTEXT.get().items():
            setattr(record, key, value)
        for key in ("scan_id", "agent_id", "approval_id"):
            if not hasattr(record, key):
                setattr(record, key, "-")
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
            "scan_id": getattr(record, "scan_id", "-"),
            "agent_id": getattr(record, "agent_id", "-"),
            "approval_id": getattr(record, "approval_id", "-"),
        }
        return json.dumps(payload, sort_keys=True)


def bind_log_context(**values: str) -> None:
    """Bind correlation fields for logs emitted in the current async context."""
    current = dict(_LOG_CONTEXT.get())
    current.update({key: str(value) for key, value in values.items()})
    _LOG_CONTEXT.set(current)


def clear_log_context() -> None:
    """Clear correlation fields for the current async context."""
    _LOG_CONTEXT.set({})


def increment_metric(name: str, value: float = 1.0) -> None:
    """Increment a process metric used by the operational dashboard."""
    with _METRICS_LOCK:
        _METRICS[name] = _METRICS.get(name, 0.0) + value


def prometheus_metrics() -> str:
    """Render secret-free metrics in Prometheus text exposition format."""
    with _METRICS_LOCK:
        snapshot = dict(_METRICS)
    lines = ["# HELP networkforgeai_metric Process metric.", "# TYPE networkforgeai_metric gauge"]
    lines.extend(f"{name} {value:g}" for name, value in sorted(snapshot.items()))
    return "\n".join(lines) + "\n"


_SECRET_KEY = re.compile(
    r"(?i)(api[_-]?key|authorization|bearer|cookie|password|passwd|secret|token|private[_-]?key)"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_-]?key|authorization|bearer|cookie|password|passwd|secret|token|private[_-]?key)\b\s*[=:]\s*)([^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_JSON = re.compile(
    r'(?i)("(?:api[_-]?key|authorization|cookie|password|passwd|secret|token|private[_-]?key)"\s*:\s*")([^"]+)(")'
)


def redact_text(value: str, *, replacement: str = "[REDACTED]") -> str:
    """Redact common credential-bearing key/value pairs from operator output."""
    redacted = _SECRET_ASSIGNMENT.sub(rf"\1{replacement}", value)
    redacted = _BEARER_VALUE.sub(f"Bearer {replacement}", redacted)
    return _SECRET_JSON.sub(rf"\1{replacement}\3", redacted)


def redact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a shallow redacted mapping suitable for logs and approval details."""
    result: dict[str, Any] = {}
    for key, item in value.items():
        if _SECRET_KEY.search(str(key)):
            result[str(key)] = "[REDACTED]"
        elif isinstance(item, str):
            result[str(key)] = redact_text(item)
        else:
            result[str(key)] = item
    return result


def redact_command(command: Sequence[str]) -> list[str]:
    """Redact option values while preserving a useful command shape."""
    redacted: list[str] = []
    redact_next = False
    for argument in command:
        text = str(argument)
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue
        option = text.lstrip("-").split("=", 1)[0]
        if _SECRET_KEY.search(option):
            if "=" in text:
                redacted.append(text.split("=", 1)[0] + "=[REDACTED]")
            else:
                redacted.append(text)
                redact_next = True
            continue
        redacted.append(redact_text(text))
    return redacted


def safe_command_string(command: Sequence[str]) -> str:
    """Render a shell-like command without exposing credential values."""
    return shlex.join(redact_command(command))


def command_digest(command: Sequence[str]) -> str:
    """Return a stable SHA-256 digest for the exact executable argument vector."""
    canonical = "\0".join(str(item) for item in command).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def configure_logging(
    level: str | None = None,
    *,
    log_format: str | None = None,
    force: bool = False,
) -> None:
    """Configure root logging once, honoring ``level`` or ``$LOG_LEVEL``.

    Idempotent: repeated calls are no-ops unless ``force`` is set. The level is
    resolved from the ``level`` argument, then ``$LOG_LEVEL``, then ``INFO``.
    An unrecognized level falls back to ``INFO`` rather than raising.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    resolved = (level or os.getenv("LOG_LEVEL") or "INFO").upper()
    resolved_format = (log_format or os.getenv("LOG_FORMAT") or "text").lower()
    if resolved_format not in {"text", "json"}:
        resolved_format = "text"
    numeric = getattr(logging, resolved, logging.INFO)
    if not isinstance(numeric, int):
        numeric = logging.INFO

    logging.basicConfig(level=numeric, format=_DEFAULT_FORMAT, force=force)
    logging.getLogger().setLevel(numeric)
    root = logging.getLogger()
    context_filter = _ContextFilter()
    for handler in root.handlers:
        handler.addFilter(context_filter)
        if resolved_format == "json":
            handler.setFormatter(_JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT))
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger. Thin wrapper for call-site consistency."""
    return logging.getLogger(name)
