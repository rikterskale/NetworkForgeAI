"""Tests for the configurable, fail-closed sandbox runner."""

import subprocess
from types import SimpleNamespace

import pytest

from networkforgeai.sandbox.runner import SandboxRunner, SandboxUnavailable


def _capture_docker(monkeypatch):
    calls: dict = {}
    monkeypatch.setenv("NETWORKFORGE_SANDBOX_IMAGE", "image:ci")
    monkeypatch.setattr(
        "networkforgeai.sandbox.runner.shutil.which", lambda name: "/usr/bin/docker"
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: calls.setdefault("command", command) or SimpleNamespace(),
    )
    return calls


def test_defaults_are_locked_down(monkeypatch):
    calls = _capture_docker(monkeypatch)
    SandboxRunner().run(["nmap", "example.com"], timeout=1)
    cmd = calls["command"]
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "--cap-drop" in cmd and cmd[cmd.index("--cap-drop") + 1] == "ALL"
    assert "--cap-add" not in cmd


def test_network_and_caps_are_configurable(monkeypatch):
    calls = _capture_docker(monkeypatch)
    monkeypatch.setenv("NETWORKFORGE_SANDBOX_NETWORK", "bridge")
    monkeypatch.setenv("NETWORKFORGE_SANDBOX_CAPS", "NET_RAW, net_admin")
    SandboxRunner().run(["nmap", "-sS", "example.com"], timeout=1)
    cmd = calls["command"]
    assert cmd[cmd.index("--network") + 1] == "bridge"
    assert cmd.count("--cap-add") == 2
    assert "NET_RAW" in cmd and "NET_ADMIN" in cmd


def test_invalid_network_mode_is_rejected(monkeypatch):
    monkeypatch.setenv("NETWORKFORGE_SANDBOX_NETWORK", "wide-open")
    with pytest.raises(SandboxUnavailable):
        SandboxRunner()


def test_invalid_capability_is_rejected():
    with pytest.raises(SandboxUnavailable):
        SandboxRunner(cap_add=["SYS_ADMIN"])


def test_missing_image_fails_closed(monkeypatch):
    monkeypatch.delenv("NETWORKFORGE_SANDBOX_IMAGE", raising=False)
    with pytest.raises(SandboxUnavailable):
        SandboxRunner().run(["nmap"], timeout=1)
