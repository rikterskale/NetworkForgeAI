#!/usr/bin/env python3
"""Production user-readiness gate for local and CI execution."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(
    name: str,
    command: list[str],
    checks: list[dict[str, object]],
    environment: dict[str, str] | None = None,
) -> None:
    env = os.environ.copy()
    if environment:
        env.update(environment)
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, env=env)
    checks.append(
        {
            "name": name,
            "passed": result.returncode == 0,
            "command": command,
            "output": (result.stdout + result.stderr)[-2000:],
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    checks: list[dict[str, object]] = []
    python = sys.executable

    compile_script = textwrap.dedent(
        """
        import py_compile
        import tempfile
        from pathlib import Path
        root = Path.cwd()
        sources = [path for folder in ("networkforgeai", "tests", "tools") for path in (root / folder).rglob("*.py")]
        with tempfile.TemporaryDirectory() as directory:
            for index, source in enumerate(sources):
                py_compile.compile(str(source), cfile=str(Path(directory) / f"{index}.pyc"), doraise=True)
        """
    )
    run("python compilation", [python, "-c", compile_script], checks)
    run("CLI help", [python, "-m", "networkforgeai.cli", "--help"], checks)
    run("CLI version", [python, "-m", "networkforgeai.cli", "--version"], checks)
    run("CLI tool inventory", [python, "-m", "networkforgeai.cli", "--list-tools"], checks)
    run(
        "safe CLI dry run",
        [
            python,
            "-m",
            "networkforgeai.cli",
            "--target",
            "example.com",
            "--scope",
            "example.com",
            "--tool",
            "nmap",
            "--dry-run",
        ],
        checks,
    )
    report_script = """
from pathlib import Path
from tempfile import TemporaryDirectory
from networkforgeai.cli import _list_reports, _read_report
with TemporaryDirectory() as directory:
    root = Path(directory)
    report = root / "scan" / "report.md"
    report.parent.mkdir()
    report.write_text("# readiness")
    assert _list_reports(directory) == ["scan/report.md"]
    assert _read_report(directory, "scan/report.md") == "# readiness"
    try:
        _read_report(directory, "../outside")
    except ValueError:
        pass
    else:
        raise SystemExit("report path escaped output directory")
"""
    run("CLI report path safety", [python, "-c", report_script], checks)

    if importlib.util.find_spec("pydantic"):
        run(
            "configuration validation",
            [python, "-m", "networkforgeai.cli", "--validate-config"],
            checks,
            {"TARGET_SCOPE": "example.com", "DASHBOARD_AUTH_TOKEN": "readiness-token"},
        )
    else:
        checks.append(
            {
                "name": "configuration validation",
                "passed": True,
                "skipped": True,
                "reason": "pydantic unavailable; runtime CI installs project dependencies",
            }
        )
    run("documentation audit", [python, "tools/ci_docs_audit.py"], checks)
    report_format_script = (
        "from networkforgeai.reporting import to_csv, to_json, to_sarif; "
        "f=[{'type':'readiness','target':'example.com'}]; "
        "assert 'readiness' in to_json(f); assert 'target' in to_csv(f); "
        "assert '2.1.0' in to_sarif(f)"
    )
    run("report format generation", [python, "-c", report_format_script], checks)

    gate_script = (
        "from networkforgeai.reporting import Severity; "
        "from tools.ci_findings_gate import blocking_findings; "
        "assert len(blocking_findings([{'type':'x','target':'t','severity':'high'}], Severity.HIGH)) == 1; "
        "assert not blocking_findings([{'type':'x','target':'t','severity':'critical','status':'remediated'}], Severity.HIGH)"
    )
    run("CI findings policy gate", [python, "-c", gate_script], checks)

    dashboard_script = """
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from fastapi.testclient import TestClient
with TemporaryDirectory() as directory:
    os.environ["DASHBOARD_AUTH_TOKEN"] = "readiness-token"
    os.environ["REPORT_OUTPUT_DIR"] = directory
    from networkforgeai.interface.dashboard import app
    root = Path(directory) / "scan-1"
    root.mkdir()
    (root / "findings.json").write_text("[]")
    (root / "scan_state.json").write_text(json.dumps({"scan_id": "scan-1", "status": "completed", "config": {"target": "example.com"}}))
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/reports").status_code == 401
    headers = {"Authorization": "Bearer readiness-token"}
    assert client.get("/reports", headers=headers).status_code == 200
    assert client.get("/reports/scan-1/findings.json", headers=headers).json()["content"] == []
    assert client.get("/scans", headers=headers).json()["scans"][0]["scan_id"] == "scan-1"
"""
    if importlib.util.find_spec("fastapi"):
        run("authenticated dashboard read-only API", [python, "-c", dashboard_script], checks)
    else:
        checks.append(
            {
                "name": "authenticated dashboard read-only API",
                "passed": True,
                "skipped": True,
                "reason": "FastAPI unavailable; runtime CI installs project dependencies",
            }
        )

    policy_script = (
        "from networkforgeai.core.scope import ScopePolicy; "
        "assert not ScopePolicy([]).contains('example.com'); "
        "assert ScopePolicy(['example.com']).contains('www.example.com')"
    )
    run("scope safety defaults", [python, "-c", policy_script], checks)

    approval_script = "\n".join(
        [
            "from networkforgeai.tools import HydraTool",
            "from networkforgeai.core.scope import ScopePolicy",
            "t = HydraTool()",
            "t.scope_policy = ScopePolicy(['example.com'])",
            "try:",
            "    t.execute('example.com', {'username': 'u', 'password': 'p'})",
            "except PermissionError:",
            "    pass",
            "else:",
            "    raise SystemExit(1)",
        ]
    )
    run("high-risk fail-closed safety", [python, "-c", approval_script], checks)

    if shutil.which("docker"):
        run("Docker Compose configuration", ["docker", "compose", "config", "--quiet"], checks)
    else:
        checks.append(
            {
                "name": "Docker Compose configuration",
                "passed": True,
                "skipped": True,
                "reason": "docker unavailable",
            }
        )

    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    checks.append(
        {
            "name": "example configuration contains no live credentials",
            "passed": "your_openai_api_key_here" in env_example and "sk-" not in env_example,
        }
    )

    result = {"passed": all(bool(check.get("passed")) for check in checks), "checks": checks}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for check in checks:
            print(f"{'PASS' if check.get('passed') else 'FAIL'} {check['name']}")
            if not check.get("passed"):
                print(check.get("output", ""))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
