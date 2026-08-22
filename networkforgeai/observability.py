"""Central logging configuration.

The framework logs through the standard :mod:`logging` module. Call
:func:`configure_logging` once at process start (the CLI and dashboard do) so
the configured ``LOG_LEVEL`` is honored consistently. Library code must only
call ``logging.getLogger(__name__)`` and never configure handlers itself.
"""

from __future__ import annotations

import logging
import os

_CONFIGURED = False

_DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"


def configure_logging(level: str | None = None, *, force: bool = False) -> None:
    """Configure root logging once, honoring ``level`` or ``$LOG_LEVEL``.

    Idempotent: repeated calls are no-ops unless ``force`` is set. The level is
    resolved from the ``level`` argument, then ``$LOG_LEVEL``, then ``INFO``.
    An unrecognized level falls back to ``INFO`` rather than raising.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    resolved = (level or os.getenv("LOG_LEVEL") or "INFO").upper()
    numeric = getattr(logging, resolved, logging.INFO)
    if not isinstance(numeric, int):
        numeric = logging.INFO

    logging.basicConfig(level=numeric, format=_DEFAULT_FORMAT, force=force)
    logging.getLogger().setLevel(numeric)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger. Thin wrapper for call-site consistency."""
    return logging.getLogger(name)
