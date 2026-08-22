"""Secret-manager credential injection (INT-204).

Resolves tool credentials from environment variables, a dot-encoded secrets
file, or Vault-style HTTPS endpoints. Secrets are resolved at use time and
passed directly to the consumer; they are never logged, cached in plaintext
on disk, or embedded in payloads.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .notifications import HttpsJsonClient

__all__ = ["SecretRef", "SecretResolver"]

_VAULT_PREFIX = "vault:"


@dataclass
class SecretRef:
    """Reference to a secret: ``env:NAME``, ``file:/path``, or ``vault:URL``.

    Plain values are rejected to discourage hardcoding secrets.
    """

    reference: str
    _cache: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.reference.startswith(("env:", "file:", "vault:")):
            raise ValueError(
                "secret references must start with env:, file:, or vault: "
                "(inline secrets are not allowed)"
            )

    def resolve(self) -> str:
        """Return the secret value, resolving lazily and caching in memory."""
        if self._cache is not None:
            return self._cache
        if self.reference.startswith("env:"):
            name = self.reference[4:]
            value = os.environ.get(name)
            if value is None:
                raise KeyError(f"environment variable not set: {name}")
        elif self.reference.startswith("file:"):
            path = Path(self.reference[5:])
            value = path.read_text(encoding="utf-8").strip()
            if not value:
                raise ValueError(f"secret file is empty: {path}")
        else:
            value = self._resolve_vault(self.reference[len(_VAULT_PREFIX) :])
        self._cache = value
        return value

    @staticmethod
    def _resolve_vault(url: str) -> str:
        """Fetch a secret from a Vault-style KV endpoint (``vault:URL``).

        The URL must point at an HTTPS endpoint returning JSON with a ``data``
        object containing a ``secret`` key (Vault KV v2 JSON shape).
        """
        import urllib.error

        try:
            client = HttpsJsonClient(url, headers={}, timeout=10.0)
        except ValueError as exc:
            raise ValueError(f"vault reference must use HTTPS: {exc}") from exc
        try:
            payload = _fetch_json(client.endpoint, client.timeout)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"vault request failed: {exc.code}") from exc
        try:
            return str(payload["data"]["secret"])
        except (KeyError, TypeError) as exc:
            raise ValueError("vault response missing data.secret") from exc


def _fetch_json(url: str, timeout: float) -> dict[str, Any]:
    from urllib.request import urlopen

    with urlopen(url, timeout=timeout) as response:  # nosec B310 - scheme validated by HttpsJsonClient
        parsed = json.loads(response.read().decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("vault response must be a JSON object")
    return parsed


class SecretResolver:
    """Resolve a mapping of option names to :class:`SecretRef` references."""

    def __init__(self, refs: dict[str, str]):
        self._refs = {key: SecretRef(ref) for key, ref in refs.items()}

    def resolve_all(self) -> dict[str, str]:
        """Resolve every reference; returns option-name -> secret mapping."""
        return {key: ref.resolve() for key, ref in self._refs.items()}

    def resolve_into(self, options: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of ``options`` with referenced keys substituted."""
        resolved = dict(options)
        for key, ref in self._refs.items():
            if key in resolved:
                resolved[key] = ref.resolve()
        return resolved
