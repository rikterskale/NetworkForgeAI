"""Fail-closed command runner for tool execution.

The Docker backend is intentionally explicit: host execution is never silently
substituted when sandbox mode is requested.

Network access and Linux capabilities are locked down by default (``--network
none``, ``--cap-drop ALL``) so a misconfiguration cannot leak traffic or grant
privileges. Real scanning needs egress, and some scanners (e.g. nmap SYN scans)
need ``NET_RAW``, so both are opt-in through environment variables validated
against a small allowlist:

- ``NETWORKFORGE_SANDBOX_NETWORK``  one of ``none`` (default), ``bridge``, ``host``
- ``NETWORKFORGE_SANDBOX_CAPS``     comma-separated subset of ``NET_RAW``, ``NET_ADMIN``

TCP connect scans work under the default locked-down profile once a network is
enabled; raw-socket scans additionally require ``NET_RAW``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Sequence

_ALLOWED_NETWORK_MODES = frozenset({"none", "bridge", "host"})
_ALLOWED_CAPS = frozenset({"NET_RAW", "NET_ADMIN"})


class SandboxUnavailable(RuntimeError):
    pass


class SandboxRunner:
    def __init__(
        self,
        image: str | None = None,
        *,
        network: str | None = None,
        cap_add: Sequence[str] | None = None,
    ):
        self.image = image or os.getenv("NETWORKFORGE_SANDBOX_IMAGE")
        self.network = self._resolve_network(network)
        self.cap_add = self._resolve_caps(cap_add)

    @staticmethod
    def _resolve_network(network: str | None) -> str:
        mode = (network or os.getenv("NETWORKFORGE_SANDBOX_NETWORK") or "none").lower()
        if mode not in _ALLOWED_NETWORK_MODES:
            raise SandboxUnavailable(
                f"Unsupported sandbox network mode {mode!r}; "
                f"allowed: {sorted(_ALLOWED_NETWORK_MODES)}"
            )
        return mode

    @staticmethod
    def _resolve_caps(cap_add: Sequence[str] | None) -> tuple[str, ...]:
        raw = (
            cap_add
            if cap_add is not None
            else os.getenv("NETWORKFORGE_SANDBOX_CAPS", "").split(",")
        )
        caps = tuple(c.strip().upper() for c in raw if c and c.strip())
        invalid = [c for c in caps if c not in _ALLOWED_CAPS]
        if invalid:
            raise SandboxUnavailable(
                f"Unsupported sandbox capabilities {invalid}; allowed: {sorted(_ALLOWED_CAPS)}"
            )
        return caps

    def run(self, command: Sequence[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
        if not self.image:
            raise SandboxUnavailable("NETWORKFORGE_SANDBOX_IMAGE is required for sandbox execution")
        if shutil.which("docker") is None:
            raise SandboxUnavailable("Docker is required for sandbox execution")
        wrapped = [
            "docker",
            "run",
            "--rm",
            "--network",
            self.network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]
        for cap in self.cap_add:
            wrapped += ["--cap-add", cap]
        wrapped += [self.image, *command]
        return subprocess.run(wrapped, capture_output=True, text=True, timeout=timeout, shell=False)
