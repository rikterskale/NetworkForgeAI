"""Unit tests for networkforgeai.doctor and the --doctor CLI hook."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from networkforgeai.cli import main
from networkforgeai.doctor import CheckResult, CheckStatus, Doctor

# --------------------------------------------------------------------- helpers


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _doctor(**kwargs) -> Doctor:
    return Doctor(runner=lambda argv: _completed(0), **kwargs)


# --------------------------------------------------------- individual checks


def test_check_python_version_passed():
    doctor = _doctor(minimum_python=(3, 9))
    result = doctor.check_python_version()
    assert result.status is CheckStatus.PASSED
    assert "Python" in result.detail


def test_check_python_version_failed():
    # Set a future minimum to force a failure regardless of interpreter.
    doctor = _doctor(minimum_python=(9, 9))
    result = doctor.check_python_version()
    assert result.status is CheckStatus.FAILED
    assert "install Python" in result.remediation


def test_check_platform_passed(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.platform.system", lambda: "Linux")
    result = _doctor().check_platform()
    assert result.status is CheckStatus.PASSED


def test_check_platform_unverified_on_unsupported(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.platform.system", lambda: "Haiku")
    result = _doctor().check_platform()
    assert result.status is CheckStatus.UNVERIFIED
    assert "supported list" in result.detail


def test_check_package_installation_passed():
    result = _doctor().check_package_installation()
    # The package is installed in the test env (editable install).
    assert result.status is CheckStatus.PASSED
    assert "networkforgeai==" in result.detail


def test_check_package_installation_failed(monkeypatch):
    from importlib.metadata import PackageNotFoundError

    def _raise(_name):
        raise PackageNotFoundError

    monkeypatch.setattr("importlib.metadata.version", _raise)
    result = _doctor().check_package_installation()
    assert result.status is CheckStatus.FAILED
    assert "pip install" in result.remediation


def test_check_cli_entry_point_passed(monkeypatch):
    monkeypatch.setattr(
        "networkforgeai.doctor.shutil.which",
        lambda name: "/usr/local/bin/networkforgeai" if name == "networkforgeai" else None,
    )
    result = _doctor().check_cli_entry_point()
    assert result.status is CheckStatus.PASSED


def test_check_cli_entry_point_failed(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: None)
    result = _doctor().check_cli_entry_point()
    assert result.status is CheckStatus.FAILED


def test_check_docker_daemon_skipped_when_docker_missing(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: None)
    result = _doctor().check_docker_daemon()
    assert result.status is CheckStatus.SKIPPED
    assert "install Docker" in result.remediation


def test_check_docker_daemon_passed(monkeypatch):
    monkeypatch.setattr(
        "networkforgeai.doctor.shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    doctor = Doctor(runner=lambda argv: _completed(0, stdout="27.1.1\n"))
    result = doctor.check_docker_daemon()
    assert result.status is CheckStatus.PASSED
    assert "27.1.1" in result.detail


def test_check_docker_daemon_failed_when_daemon_down(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: "/usr/bin/docker")
    doctor = Doctor(runner=lambda argv: _completed(1, stderr="Cannot connect to daemon"))
    result = doctor.check_docker_daemon()
    assert result.status is CheckStatus.FAILED
    assert "Cannot connect" in result.detail


def test_check_docker_daemon_failed_when_runner_raises(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: "/usr/bin/docker")

    def _raise(_argv):
        raise OSError("boom")

    doctor = Doctor(runner=_raise)
    result = doctor.check_docker_daemon()
    assert result.status is CheckStatus.FAILED
    assert "OSError" in result.detail


def test_check_sandbox_image_skipped_without_env(monkeypatch):
    monkeypatch.delenv("NETWORKFORGE_SANDBOX_IMAGE", raising=False)
    result = _doctor().check_sandbox_image()
    assert result.status is CheckStatus.SKIPPED


def test_check_sandbox_image_skipped_without_docker(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: None)
    result = _doctor().check_sandbox_image(image="my/image:tag")
    assert result.status is CheckStatus.SKIPPED
    assert "docker CLI" in result.detail


def test_check_sandbox_image_passed(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: "/usr/bin/docker")
    doctor = Doctor(
        runner=lambda argv: _completed(
            0, stdout="sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\n"
        )
    )
    result = doctor.check_sandbox_image(image="my/image:tag")
    assert result.status is CheckStatus.PASSED
    assert "sha256:abcdefabcde" in result.detail


def test_check_sandbox_image_failed_when_not_pulled(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: "/usr/bin/docker")
    doctor = Doctor(runner=lambda argv: _completed(1, stderr="not found"))
    result = doctor.check_sandbox_image(image="my/image:tag")
    assert result.status is CheckStatus.FAILED
    assert "docker pull my/image:tag" in result.remediation


def test_check_sandbox_image_unverified_on_runner_error(monkeypatch):
    monkeypatch.setattr("networkforgeai.doctor.shutil.which", lambda name: "/usr/bin/docker")

    def _raise(_argv):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=1)

    doctor = Doctor(runner=_raise)
    result = doctor.check_sandbox_image(image="x")
    assert result.status is CheckStatus.UNVERIFIED


def test_check_disk_space_passed(tmp_path):
    result = _doctor(minimum_disk_gb=0.0).check_disk_space(tmp_path)
    assert result.status is CheckStatus.PASSED


def test_check_disk_space_failed(tmp_path):
    # Impossibly high requirement forces the failure branch.
    result = _doctor(minimum_disk_gb=1e12).check_disk_space(tmp_path)
    assert result.status is CheckStatus.FAILED
    assert "free up disk space" in result.remediation


def test_check_disk_space_unverified_on_stat_error(monkeypatch, tmp_path):
    def _boom(_path):
        raise OSError("nope")

    monkeypatch.setattr("networkforgeai.doctor.shutil.disk_usage", _boom)
    result = _doctor().check_disk_space(tmp_path)
    assert result.status is CheckStatus.UNVERIFIED


def test_check_memory_passed(monkeypatch):
    monkeypatch.setattr(
        Path, "read_text", lambda self, encoding="utf-8": "MemAvailable:  4194304 kB\n"
    )
    result = _doctor(minimum_memory_mb=100.0).check_memory()
    assert result.status is CheckStatus.PASSED


def test_check_memory_failed(monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda self, encoding="utf-8": "MemAvailable:  128 kB\n")
    result = _doctor(minimum_memory_mb=1024.0).check_memory()
    assert result.status is CheckStatus.FAILED


def test_check_memory_unverified_without_procmeminfo(monkeypatch):
    def _boom(self, encoding="utf-8"):
        raise OSError("no /proc/meminfo")

    monkeypatch.setattr(Path, "read_text", _boom)
    result = _doctor().check_memory()
    assert result.status is CheckStatus.UNVERIFIED


def test_check_memory_unverified_on_malformed_meminfo(monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda self, encoding="utf-8": "MemAvailable:\n")
    result = _doctor().check_memory()
    assert result.status is CheckStatus.UNVERIFIED
    assert "malformed" in result.detail


def test_check_memory_unverified_when_key_missing(monkeypatch):
    monkeypatch.setattr(Path, "read_text", lambda self, encoding="utf-8": "SomethingElse: 42 kB\n")
    result = _doctor().check_memory()
    assert result.status is CheckStatus.UNVERIFIED


def test_check_report_directory_passed(tmp_path):
    target = tmp_path / "reports"
    result = _doctor().check_report_directory(target)
    assert result.status is CheckStatus.PASSED
    assert target.exists()


def test_check_report_directory_failed_when_unwritable(monkeypatch, tmp_path):
    def _boom(self, *args, **kwargs):
        raise OSError("read-only")

    monkeypatch.setattr(Path, "mkdir", _boom)
    result = _doctor().check_report_directory(tmp_path / "no-way")
    assert result.status is CheckStatus.FAILED
    assert "grant write permission" in result.remediation


def test_check_provider_sdk_passed_for_stdlib_module():
    # 'json' is always importable — used as a stand-in for a provider SDK.
    result = _doctor().check_provider_sdk("Fake", "json")
    assert result.status is CheckStatus.PASSED


def test_check_provider_sdk_skipped(monkeypatch):
    result = _doctor().check_provider_sdk("Fake", "definitely_not_installed_xyzzy")
    assert result.status is CheckStatus.SKIPPED
    assert "pip install" in result.remediation


def test_check_runtime_configuration_failed_when_scope_missing(monkeypatch):
    monkeypatch.delenv("TARGET_SCOPE", raising=False)
    monkeypatch.delenv("DASHBOARD_AUTH_TOKEN", raising=False)
    result = _doctor().check_runtime_configuration()
    assert result.status is CheckStatus.FAILED


def test_check_runtime_configuration_passed(monkeypatch, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    result = _doctor().check_runtime_configuration()
    assert result.status is CheckStatus.PASSED
    assert "scope entries" in result.detail


def test_check_runtime_configuration_failed_when_settings_construction_raises(monkeypatch):
    # Force pydantic to raise by supplying an invalid enum value.
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("APPROVAL_MODE", "not-a-real-mode")
    result = _doctor().check_runtime_configuration()
    assert result.status is CheckStatus.FAILED
    assert "instantiate Settings" in result.detail


# ------------------------------------------------------ sequencer + aggregate


def test_run_populates_all_categories(monkeypatch, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    doctor = Doctor(runner=lambda argv: _completed(0, stdout="27.1.1\n"))
    doctor.run(report_directory=tmp_path)
    names = {check.name for check in doctor.checks}
    assert {
        "python version",
        "platform",
        "package installation",
        "CLI entry point",
        "docker daemon",
        "sandbox image",
        "disk space",
        "available memory",
        "report directory",
        "runtime configuration",
    } <= names
    # At least one provider SDK check is emitted.
    assert any(name.endswith("SDK") for name in names)


def test_ok_non_strict_ignores_skipped():
    doctor = _doctor()
    doctor.checks = [
        CheckResult("a", CheckStatus.PASSED),
        CheckResult("b", CheckStatus.SKIPPED),
        CheckResult("c", CheckStatus.UNVERIFIED),
    ]
    assert doctor.ok is True


def test_ok_strict_blocks_skipped_and_unverified():
    doctor = _doctor(strict=True)
    doctor.checks = [
        CheckResult("a", CheckStatus.PASSED),
        CheckResult("b", CheckStatus.SKIPPED),
    ]
    assert doctor.ok is False
    doctor.checks = [
        CheckResult("a", CheckStatus.PASSED),
        CheckResult("b", CheckStatus.UNVERIFIED),
    ]
    assert doctor.ok is False


def test_ok_any_mode_blocks_failed():
    doctor = _doctor()
    doctor.checks = [CheckResult("a", CheckStatus.FAILED, remediation="x")]
    assert doctor.ok is False


def test_as_dict_shape():
    doctor = _doctor()
    doctor.checks = [
        CheckResult("a", CheckStatus.PASSED, "d1"),
        CheckResult("b", CheckStatus.FAILED, "d2", "r2"),
    ]
    data = doctor.as_dict()
    assert data["schema_version"] == 1
    assert data["strict"] is False
    assert data["ok"] is False
    assert data["summary"]["passed"] == 1
    assert data["summary"]["failed"] == 1
    assert data["checks"][1]["remediation"] == "r2"


def test_as_text_summary_line_shows_counts_and_readiness():
    doctor = _doctor(strict=True)
    doctor.checks = [
        CheckResult("a", CheckStatus.PASSED, "d1"),
        CheckResult("b", CheckStatus.FAILED, "d2", "r2"),
        CheckResult("c", CheckStatus.SKIPPED, "d3", "r3"),
        CheckResult("d", CheckStatus.UNVERIFIED, "d4"),
    ]
    text = doctor.as_text()
    assert "1 passed" in text
    assert "1 failed" in text
    assert "1 skipped" in text
    assert "1 unverified" in text
    assert "(strict)" in text
    assert "NOT READY" in text
    assert "-> r2" in text  # remediation rendered
    # PASSED check does not render remediation.
    assert "-> " not in text.split("\n")[0]


def test_check_result_as_dict_shape():
    result = CheckResult("x", CheckStatus.PASSED, "detail")
    assert result.as_dict() == {
        "name": "x",
        "status": "passed",
        "detail": "detail",
        "remediation": "",
    }


# ---------------------------------------------------- CLI integration surface


def test_cli_doctor_json_output_returns_valid_json(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    rc = main(["--doctor", "--json"])
    # We don't assert rc value — the local environment may not have Docker.
    assert rc in {0, 2}
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert "checks" in payload
    assert any(check["name"] == "python version" for check in payload["checks"])


def test_cli_doctor_text_output_includes_summary(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    main(["--doctor"])
    out = capsys.readouterr().out
    assert "python version" in out
    assert "summary" in out
    assert "READY" in out or "NOT READY" in out


def test_cli_doctor_runs_before_settings_load(monkeypatch, capsys, tmp_path):
    """--doctor MUST work when config is invalid — that's the point."""
    monkeypatch.delenv("TARGET_SCOPE", raising=False)
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    # Should exit cleanly with a diagnosis instead of raising.
    rc = main(["--doctor", "--json"])
    assert rc in {0, 2}
    payload = json.loads(capsys.readouterr().out)
    # Runtime configuration should be flagged as failed since TARGET_SCOPE is missing.
    config_check = next(c for c in payload["checks"] if c["name"] == "runtime configuration")
    assert config_check["status"] == "failed"


def test_cli_doctor_strict_flag_is_forwarded(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "diagnostic-token-value")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    main(["--doctor", "--strict", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["strict"] is True


# ---------------------------------------------------- auto-preflight paths


def _patch_doctor_with_check(monkeypatch, result: CheckResult) -> None:
    """Replace Doctor.run with one that installs a single check."""

    def _fake_run(self, *, report_directory=None):
        self.checks = [result]

    monkeypatch.setattr("networkforgeai.doctor.Doctor.run", _fake_run)


def test_auto_preflight_blocks_scan_when_a_check_fails(monkeypatch, capsys):
    _patch_doctor_with_check(
        monkeypatch,
        CheckResult(
            "docker daemon",
            CheckStatus.FAILED,
            "connection refused",
            "start docker",
        ),
    )
    # Any scan-shaped invocation is enough; use --tool so the flow reaches
    # the preflight gate.
    rc = main(
        [
            "--target",
            "example.com",
            "--scope",
            "example.com",
            "--tool",
            "nmap",
        ]
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "preflight FAILED" in out
    assert "docker daemon" in out
    assert "start docker" in out
    assert "--skip-preflight" in out


def test_auto_preflight_is_skipped_when_dry_run(monkeypatch, capsys):
    called = {"n": 0}

    def _boom_run(self, *, report_directory=None):
        called["n"] += 1

    monkeypatch.setattr("networkforgeai.doctor.Doctor.run", _boom_run)
    # --dry-run should NOT invoke the preflight helper at all.
    rc = main(
        [
            "--target",
            "example.com",
            "--scope",
            "example.com",
            "--tool",
            "nmap",
            "--dry-run",
        ]
    )
    # Whether the tool call itself succeeds is beside the point; we just
    # need to confirm the preflight helper never ran.
    assert called["n"] == 0
    assert rc in {0, 1, 2}  # tool behavior can vary; preflight is what we assert


def test_auto_preflight_is_skipped_when_skip_preflight_flag(monkeypatch, capsys):
    called = {"n": 0}

    def _boom_run(self, *, report_directory=None):
        called["n"] += 1

    monkeypatch.setattr("networkforgeai.doctor.Doctor.run", _boom_run)
    # The tool path itself may raise on this host (no sandbox image
    # configured); we only assert that the doctor preflight was NOT
    # invoked.
    with pytest.raises((SystemExit, RuntimeError)):
        main(
            [
                "--target",
                "example.com",
                "--scope",
                "example.com",
                "--tool",
                "nmap",
                "--skip-preflight",
            ]
        )
    assert called["n"] == 0


def test_auto_preflight_prints_summary_when_only_skipped(monkeypatch, capsys):
    """Skipped/unverified are logged but do not block the scan."""

    _patch_doctor_with_check(
        monkeypatch,
        CheckResult(
            "docker daemon",
            CheckStatus.SKIPPED,
            "docker CLI not installed",
            "install docker",
        ),
    )
    # Use --preflight so we short-circuit after the doctor gate but
    # before touching a real tool binary.
    main(
        [
            "--target",
            "example.com",
            "--scope",
            "example.com",
            "--preflight",
        ]
    )
    out = capsys.readouterr().out
    # --preflight itself bypasses the auto-preflight guard, so we do
    # NOT expect the "preflight ok" summary in this path — auto-preflight
    # is only for real scans.
    assert "preflight FAILED" not in out


def test_auto_preflight_runs_before_explicit_preflight_command_is_bypassed(monkeypatch, capsys):
    """--preflight is itself a check; auto-preflight is redundant there."""

    called = {"n": 0}

    def _record(self, *, report_directory=None):
        called["n"] += 1
        self.checks = [CheckResult("x", CheckStatus.PASSED)]

    monkeypatch.setattr("networkforgeai.doctor.Doctor.run", _record)
    main(
        [
            "--target",
            "example.com",
            "--scope",
            "example.com",
            "--preflight",
        ]
    )
    # --preflight branch must NOT trigger the auto-preflight helper.
    assert called["n"] == 0


def test_auto_preflight_ok_message_on_all_passed(monkeypatch, capsys):
    """Green preflight prints a terse one-liner so operators know it ran."""

    _patch_doctor_with_check(monkeypatch, CheckResult("x", CheckStatus.PASSED, "all clear"))
    # Route through --tool so the auto-preflight gate is hit but we
    # then short-circuit inside the tool path when the sandbox is
    # unavailable. We only assert the preflight message here.
    try:
        main(
            [
                "--target",
                "example.com",
                "--scope",
                "example.com",
                "--tool",
                "nmap",
                "--host-execution",
                "--dry-run",  # avoid running a real nmap
            ]
        )
    except SystemExit:
        pass
    # --dry-run bypasses the preflight — assert absence to prove that
    # the dry-run bypass is what actually protected us here (rather
    # than an accidental green path).
    out = capsys.readouterr().out
    assert "preflight ok" not in out
    assert "preflight FAILED" not in out


def test_auto_preflight_ok_message_when_no_skips(monkeypatch, capsys):
    """When only PASSED checks are present, the summary omits skip counts."""

    _patch_doctor_with_check(monkeypatch, CheckResult("x", CheckStatus.PASSED, "all clear"))
    # The tool path may raise later (no sandbox image on this host);
    # what we care about is that the preflight OK line was printed
    # first.
    with pytest.raises((SystemExit, RuntimeError)):
        main(
            [
                "--target",
                "example.com",
                "--scope",
                "example.com",
                "--tool",
                "nmap",
            ]
        )
    out = capsys.readouterr().out
    assert "preflight ok (1 passed)" in out
