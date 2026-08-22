"""Fail-closed checks performed before a tool execution starts."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from ..observability import command_digest
from .base_tool import BaseTool


def preflight_tool(tool: BaseTool, target: str) -> dict[str, Any]:
    """Return a secret-safe prerequisite report for one configured tool.

    Host binaries are checked only for host execution. Sandbox execution checks
    Docker and the configured image, because scanner binaries live inside the
    image rather than on the operator's PATH.
    """
    report: dict[str, Any] = {
        "tool": tool.name,
        "target": target,
        "sandbox": tool.sandbox_mode,
        "status": "passed",
        "checks": [],
    }

    if not tool.validate_target(target):
        report["checks"].append({"name": "scope", "status": "failed", "detail": "out of scope"})
        report["status"] = "failed"
        report["ok"] = False
        return report
    report["checks"].append({"name": "scope", "status": "passed"})

    try:
        command = tool.build_command(target)
    except Exception as exc:
        report["checks"].append(
            {"name": "command", "status": "failed", "detail": f"{type(exc).__name__}: {exc}"}
        )
        report["status"] = "failed"
        report["ok"] = False
        return report
    executable = command[0] if command else ""
    report["command_digest"] = command_digest(command)
    report["executable"] = executable

    if tool.dry_run:
        report["checks"].append(
            {"name": "executable", "status": "skipped", "detail": "dry-run does not execute"}
        )
    elif tool.sandbox_mode:
        docker = shutil.which("docker")
        image = tool.get_info().get("sandbox_image")
        image = image or os.getenv("NETWORKFORGE_SANDBOX_IMAGE")
        if not docker:
            report["checks"].append(
                {"name": "docker", "status": "failed", "detail": "docker executable not found"}
            )
        elif not image:
            report["checks"].append(
                {"name": "sandbox_image", "status": "failed", "detail": "not configured"}
            )
        else:
            try:
                result = subprocess.run(
                    [docker, "image", "inspect", str(image)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                status = "passed" if result.returncode == 0 else "failed"
                detail = str(image) if result.returncode == 0 else f"image unavailable: {image}"
            except (OSError, subprocess.TimeoutExpired) as exc:
                status = "failed"
                detail = f"docker inspection failed: {type(exc).__name__}"
            report["checks"].append({"name": "sandbox_image", "status": status, "detail": detail})
    elif shutil.which(executable):
        report["checks"].append({"name": "executable", "status": "passed", "detail": executable})
    else:
        report["checks"].append(
            {"name": "executable", "status": "failed", "detail": f"{executable!r} not found"}
        )

    report["ok"] = all(check["status"] in {"passed", "skipped"} for check in report["checks"])
    if not report["ok"]:
        report["status"] = "failed"
    return report
