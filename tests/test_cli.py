"""End-to-end tests for the CLI entry point."""

import json
from pathlib import Path

import pytest

from networkforgeai.cli import build_parser, main
from networkforgeai.tools import get_available_tools


def test_parser_exposes_all_registered_tools():
    parser = build_parser()
    tool_action = next(a for a in parser._actions if a.dest == "tool")
    assert set(tool_action.choices) == set(get_available_tools())
    # Previously-hidden high-risk tools are now selectable.
    assert {"sqlmap", "hydra", "metasploit"} <= set(tool_action.choices)


def test_list_tools(capsys):
    assert main(["--list-tools"]) == 0
    out = capsys.readouterr().out
    assert "nmap" in out
    assert "sqlmap" in out


def test_list_and_show_reports(tmp_path, capsys):
    report = tmp_path / "run1" / "report.md"
    report.parent.mkdir(parents=True)
    report.write_text("# hello", encoding="utf-8")

    assert main(["--list-reports", "--output-dir", str(tmp_path)]) == 0
    listed = capsys.readouterr().out
    assert "run1/report.md" in listed

    assert main(["--show-report", "run1/report.md", "--output-dir", str(tmp_path)]) == 0
    assert "# hello" in capsys.readouterr().out


def test_show_report_escape_is_rejected(tmp_path):
    with pytest.raises(SystemExit):
        main(["--show-report", "../etc/passwd", "--output-dir", str(tmp_path)])


def test_validate_config(monkeypatch, capsys):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("DASHBOARD_AUTH_TOKEN", "a-real-token")
    assert main(["--validate-config"]) == 0
    assert "valid" in capsys.readouterr().out.lower()


def test_scan_requires_target_and_scope():
    with pytest.raises(SystemExit):
        main([])


def test_target_outside_scope_is_rejected():
    with pytest.raises(SystemExit):
        main(["--target", "evil.test", "--scope", "example.com"])


def test_single_tool_dry_run(capsys):
    rc = main(["--target", "example.com", "--scope", "example.com", "--tool", "nmap", "--dry-run"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool_name"] == "nmap"
    assert payload["success"] is True


def test_scan_uses_environment_runtime_defaults(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("TARGET_SCOPE", "example.com")
    monkeypatch.setenv("APPROVAL_MODE", "moderate")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("REPORT_FORMATS", '["json"]')

    assert main(["--target", "example.com", "--orchestrate", "--dry-run"]) == 0
    capsys.readouterr()

    states = list(tmp_path.glob("*/scan_state.json"))
    assert states
    state = json.loads(states[0].read_text(encoding="utf-8"))
    assert state["config"]["scope"] == ["example.com"]
    assert state["config"]["approval_mode"] == "moderate"
    assert state["config"]["report_formats"] == ["json"]
    assert not (states[0].parent / "report.md").exists()


def test_orchestrated_dry_run_produces_only_real_findings(tmp_path, capsys):
    rc = main(
        [
            "--target",
            "localhost",
            "--scope",
            "localhost",
            "--orchestrate",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert rc == 0

    findings_files = list(Path(tmp_path).glob("*/findings.json"))
    assert findings_files, "expected a findings.json to be written"
    findings = json.loads(findings_files[0].read_text(encoding="utf-8"))
    # Only honest, tool/DNS-sourced findings — no fabricated vulnerabilities.
    for finding in findings:
        assert finding.get("source", "").startswith(("dns:", "tool:"))
        assert finding["type"] != "sql_injection" or finding.get("validated") is True
