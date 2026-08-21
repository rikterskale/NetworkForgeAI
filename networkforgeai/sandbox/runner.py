"""Fail-closed command runner for tool execution.

The Docker backend is intentionally explicit: host execution is never silently
substituted when sandbox mode is requested.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Sequence


class SandboxUnavailable(RuntimeError):
    pass


class SandboxRunner:
    def __init__(self, image: str | None = None):
        self.image = image or os.getenv("NETWORKFORGE_SANDBOX_IMAGE")

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
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            self.image,
            *command,
        ]
        return subprocess.run(wrapped, capture_output=True, text=True, timeout=timeout, shell=False)
