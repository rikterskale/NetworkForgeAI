"""Comprehensive readiness diagnostics for NetworkForgeAI.

The ``doctor`` command runs a fixed set of checks covering the
operator's environment, the runtime configuration, the sandbox
container image, and the writability of the report directory. Each
check reports one of four states:

* ``passed`` — the prerequisite is satisfied.
* ``failed`` — the prerequisite is required and is not satisfied.
  Every failed check carries a ``remediation`` string an operator can
  act on directly.
* ``skipped`` — an optional dependency is not installed (e.g. Docker
  when host execution is planned). Not a failure by default; the
  ``--strict`` flag promotes skipped checks to failure so a CI
  readiness gate cannot pass by silently omitting coverage.
* ``unverified`` — the prerequisite could not be inspected for
  environmental reasons unrelated to the operator (e.g. reading
  ``/proc/meminfo`` on a non-Linux host). ``--strict`` also promotes
  these.

Every check is a small pure method that returns a
:class:`CheckResult`. Individual checks are unit-tested; the
:meth:`Doctor.run` sequencer wires them together. Secrets are never
included in ``detail`` or ``remediation`` — only structural
information (presence, version, digest prefix).
"""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import subprocess  # noqa: S404 - Docker / uname probes are the whole point
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str = ""
    remediation: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "remediation": self.remediation,
        }


# A tiny type alias for the subprocess runner so tests can inject a fake.
Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def _default_runner(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(  # noqa: S603 - argv built from a fixed list, no shell
        argv, capture_output=True, text=True, timeout=10, check=False
    )


@dataclass
class Doctor:
    """Runs the configured checks and aggregates their results."""

    strict: bool = False
    minimum_python: tuple[int, int] = (3, 11)
    minimum_disk_gb: float = 1.0
    minimum_memory_mb: float = 512.0
    supported_platforms: tuple[str, ...] = ("Linux", "Darwin", "Windows")
    llm_providers: tuple[tuple[str, str], ...] = (
        ("OpenAI", "openai"),
        ("Anthropic", "anthropic"),
        ("Google", "google.genai"),
        ("LiteLLM", "litellm"),
    )
    runner: Runner = field(default=_default_runner, repr=False)
    checks: list[CheckResult] = field(default_factory=list)

    # ----- result construction helpers ------------------------------

    @staticmethod
    def _passed(name: str, detail: str = "") -> CheckResult:
        return CheckResult(name, CheckStatus.PASSED, detail)

    @staticmethod
    def _failed(name: str, detail: str, remediation: str) -> CheckResult:
        return CheckResult(name, CheckStatus.FAILED, detail, remediation)

    @staticmethod
    def _skipped(name: str, detail: str, remediation: str = "") -> CheckResult:
        return CheckResult(name, CheckStatus.SKIPPED, detail, remediation)

    @staticmethod
    def _unverified(name: str, detail: str, remediation: str = "") -> CheckResult:
        return CheckResult(name, CheckStatus.UNVERIFIED, detail, remediation)

    # ----- individual checks ----------------------------------------

    def check_python_version(self) -> CheckResult:
        v = sys.version_info
        detail = f"Python {v.major}.{v.minor}.{v.micro}"
        if (v.major, v.minor) >= self.minimum_python:
            return self._passed("python version", detail)
        need = f"{self.minimum_python[0]}.{self.minimum_python[1]}"
        return self._failed(
            "python version",
            f"{detail} (require >= {need})",
            f"install Python >= {need}",
        )

    def check_platform(self) -> CheckResult:
        system = platform.system()
        detail = f"{system} {platform.release()} ({platform.machine()})"
        if system in self.supported_platforms:
            return self._passed("platform", detail)
        return self._unverified(
            "platform",
            f"{system} is not on the supported list ({', '.join(self.supported_platforms)})",
            "run on Linux, macOS, or Windows",
        )

    def check_package_installation(self) -> CheckResult:
        try:
            from importlib.metadata import PackageNotFoundError, version
        except ImportError:  # pragma: no cover - stdlib on 3.11+
            return self._unverified(
                "package installation",
                "importlib.metadata unavailable",
            )
        try:
            v = version("networkforgeai")
        except PackageNotFoundError:
            return self._failed(
                "package installation",
                "networkforgeai distribution not found",
                "run: pip install -e '.[dev]'",
            )
        return self._passed("package installation", f"networkforgeai=={v}")

    def check_cli_entry_point(self) -> CheckResult:
        path = shutil.which("networkforgeai")
        if path:
            return self._passed("CLI entry point", path)
        return self._failed(
            "CLI entry point",
            "'networkforgeai' not on PATH",
            "run: pip install -e '.[dev]' and ensure the venv bin dir is on PATH",
        )

    def check_docker_daemon(self) -> CheckResult:
        docker = shutil.which("docker")
        if not docker:
            return self._skipped(
                "docker daemon",
                "docker CLI not installed",
                "install Docker Engine to enable sandboxed scanner execution",
            )
        try:
            result = self.runner([docker, "info", "--format", "{{.ServerVersion}}"])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._failed(
                "docker daemon",
                f"docker CLI present but info failed: {type(exc).__name__}",
                "start the Docker daemon (systemctl start docker / Docker Desktop)",
            )
        if result.returncode == 0 and result.stdout.strip():
            return self._passed(
                "docker daemon",
                f"docker server {result.stdout.strip()}",
            )
        stderr = (result.stderr or result.stdout).strip()
        return self._failed(
            "docker daemon",
            f"docker info failed: {stderr[:200]}",
            "ensure the docker daemon is running and the current user has access",
        )

    def check_sandbox_image(self, image: str | None = None) -> CheckResult:
        image = image or os.getenv("NETWORKFORGE_SANDBOX_IMAGE") or ""
        if not image:
            return self._skipped(
                "sandbox image",
                "NETWORKFORGE_SANDBOX_IMAGE not set",
                "set NETWORKFORGE_SANDBOX_IMAGE to the digest-pinned scanner image",
            )
        docker = shutil.which("docker")
        if not docker:
            return self._skipped(
                "sandbox image",
                "docker CLI not installed",
                "install Docker Engine to inspect the sandbox image",
            )
        try:
            result = self.runner([docker, "image", "inspect", image, "--format", "{{.Id}}"])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._unverified(
                "sandbox image",
                f"docker image inspect failed: {type(exc).__name__}",
                f"run: docker pull {image}",
            )
        if result.returncode == 0 and result.stdout.strip():
            digest = result.stdout.strip()
            short = digest[:19] + "..." if len(digest) > 19 else digest
            return self._passed("sandbox image", f"{image} ({short})")
        return self._failed(
            "sandbox image",
            f"image not present: {image}",
            f"run: docker pull {image}",
        )

    def check_disk_space(self, path: Path) -> CheckResult:
        try:
            usage = shutil.disk_usage(path)
        except OSError as exc:
            return self._unverified(
                "disk space",
                f"cannot stat {path}: {type(exc).__name__}",
                f"ensure {path} exists and is accessible",
            )
        free_gb = usage.free / (1024**3)
        detail = f"{free_gb:.1f} GiB free at {path}"
        if free_gb >= self.minimum_disk_gb:
            return self._passed("disk space", detail)
        return self._failed(
            "disk space",
            f"only {free_gb:.2f} GiB free at {path} (need >= {self.minimum_disk_gb} GiB)",
            f"free up disk space at {path} before starting a scan",
        )

    def check_memory(self) -> CheckResult:
        meminfo = Path("/proc/meminfo")
        try:
            text = meminfo.read_text(encoding="utf-8")
        except OSError:
            return self._unverified(
                "available memory",
                "no /proc/meminfo (non-Linux); memory check unavailable",
                "run on Linux or install psutil for a portable memory probe",
            )
        for line in text.splitlines():
            if line.startswith("MemAvailable:"):
                try:
                    kb = int(line.split()[1])
                except (IndexError, ValueError):
                    return self._unverified(
                        "available memory",
                        "malformed /proc/meminfo MemAvailable line",
                    )
                mb = kb / 1024
                if mb >= self.minimum_memory_mb:
                    return self._passed("available memory", f"{mb:.0f} MiB available")
                return self._failed(
                    "available memory",
                    f"only {mb:.0f} MiB available (need >= {self.minimum_memory_mb} MiB)",
                    "close other applications or increase the machine's RAM",
                )
        return self._unverified(
            "available memory",
            "MemAvailable not present in /proc/meminfo",
        )

    def check_report_directory(self, path: Path) -> CheckResult:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".doctor-write-probe"
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
        except OSError as exc:
            return self._failed(
                "report directory",
                f"cannot write to {path}: {type(exc).__name__}: {exc}",
                f"grant write permission to {path} or set REPORT_OUTPUT_DIR to a writable path",
            )
        return self._passed("report directory", f"writable: {path}")

    def check_provider_sdk(self, name: str, module: str) -> CheckResult:
        if importlib.util.find_spec(module) is not None:
            return self._passed(f"{name} SDK", f"{module} importable")
        return self._skipped(
            f"{name} SDK",
            f"{module} not installed",
            f"pip install '.[llm]' to enable the {name} provider",
        )

    def check_runtime_configuration(self) -> CheckResult:
        try:
            from .config import Settings
        except Exception as exc:  # pragma: no cover - defensive
            return self._unverified(
                "runtime configuration",
                f"cannot import Settings: {type(exc).__name__}: {exc}",
            )
        try:
            settings = Settings()
        except Exception as exc:
            return self._failed(
                "runtime configuration",
                f"cannot instantiate Settings(): {type(exc).__name__}: {exc}",
                "verify .env is well-formed and required variables are set",
            )
        try:
            settings.validate_runtime()
        except Exception as exc:
            return self._failed(
                "runtime configuration",
                str(exc),
                "fix the reported configuration error and re-run",
            )
        return self._passed(
            "runtime configuration",
            f"{len(settings.parsed_target_scope)} scope entries, "
            f"approval={settings.approval_mode.value}",
        )

    # ----- sequencer + aggregation ----------------------------------

    def run(self, *, report_directory: Path | str = "./reports") -> None:
        report_dir = Path(report_directory).expanduser()
        self.checks.append(self.check_python_version())
        self.checks.append(self.check_platform())
        self.checks.append(self.check_package_installation())
        self.checks.append(self.check_cli_entry_point())
        self.checks.append(self.check_docker_daemon())
        self.checks.append(self.check_sandbox_image())
        self.checks.append(self.check_disk_space(report_dir))
        self.checks.append(self.check_memory())
        self.checks.append(self.check_report_directory(report_dir))
        for name, module in self.llm_providers:
            self.checks.append(self.check_provider_sdk(name, module))
        self.checks.append(self.check_runtime_configuration())

    @property
    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CheckStatus}
        for check in self.checks:
            counts[check.status.value] += 1
        return counts

    @property
    def ok(self) -> bool:
        """True when the readiness bar has been met.

        Non-strict: only ``failed`` blocks. Strict: ``skipped`` and
        ``unverified`` also block (so CI cannot pass by omission).
        """
        if self.strict:
            blocking = {CheckStatus.FAILED, CheckStatus.SKIPPED, CheckStatus.UNVERIFIED}
        else:
            blocking = {CheckStatus.FAILED}
        return not any(check.status in blocking for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "strict": self.strict,
            "ok": self.ok,
            "summary": self.summary,
            "checks": [check.as_dict() for check in self.checks],
        }

    def as_text(self) -> str:
        symbol = {
            CheckStatus.PASSED: "PASS",
            CheckStatus.FAILED: "FAIL",
            CheckStatus.SKIPPED: "SKIP",
            CheckStatus.UNVERIFIED: "????",
        }
        lines: list[str] = []
        for check in self.checks:
            lines.append(f"[{symbol[check.status]}] {check.name}")
            if check.detail:
                lines.append(f"       {check.detail}")
            if check.status is not CheckStatus.PASSED and check.remediation:
                lines.append(f"       -> {check.remediation}")
        counts = self.summary
        strict_label = " (strict)" if self.strict else ""
        lines.append("")
        lines.append(
            f"summary{strict_label}: "
            f"{counts['passed']} passed, {counts['failed']} failed, "
            f"{counts['skipped']} skipped, {counts['unverified']} unverified"
        )
        lines.append("READY" if self.ok else "NOT READY")
        return "\n".join(lines)
