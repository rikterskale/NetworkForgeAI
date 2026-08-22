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


def run_expect_failure(
    name: str,
    command: list[str],
    checks: list[dict[str, object]],
    expected_text: str,
) -> None:
    """Pass only when a safety-critical command rejects invalid input."""
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    output = result.stdout + result.stderr
    checks.append(
        {
            "name": name,
            "passed": result.returncode != 0 and expected_text in output,
            "command": command,
            "output": output[-2000:],
            "expected_text": expected_text,
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when an optional readiness check is skipped (recommended for CI)",
    )
    args = parser.parse_args()
    checks: list[dict[str, object]] = []
    python = sys.executable
    cli_candidates = [shutil.which("networkforgeai"), str(Path(python).with_name("networkforgeai"))]
    installed_cli = next(
        (candidate for candidate in cli_candidates if candidate and Path(candidate).is_file()), None
    )
    checks.append(
        {
            "name": "installed CLI entry point",
            "passed": installed_cli is not None,
            "path": installed_cli or "",
        }
    )

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
    run(
        "CLI help exposes safety controls",
        [
            python,
            "-c",
            "import subprocess, sys; output = subprocess.check_output([sys.executable, '-m', 'networkforgeai.cli', '--help'], text=True); assert all(option in output for option in ('--target', '--scope', '--dry-run'))",
        ],
        checks,
    )
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
    run_expect_failure(
        "CLI rejects missing scope",
        [python, "-m", "networkforgeai.cli", "--target", "example.com", "--dry-run"],
        checks,
        "--target and --scope are required",
    )
    run_expect_failure(
        "CLI rejects out-of-scope target",
        [
            python,
            "-m",
            "networkforgeai.cli",
            "--target",
            "outside.example",
            "--scope",
            "example.com",
            "--dry-run",
        ],
        checks,
        "outside the explicitly supplied scope",
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
        run(
            "structured configuration diagnostics",
            [python, "-m", "networkforgeai.cli", "--diagnose-config"],
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
with TemporaryDirectory() as directory:
    os.environ["DASHBOARD_AUTH_TOKEN"] = "readiness-token"
    os.environ["REPORT_OUTPUT_DIR"] = directory
    from networkforgeai.interface.dashboard import app
    root = Path(directory) / "scan-1"
    root.mkdir()
    (root / "findings.json").write_text("[]")
    (root / "scan_state.json").write_text(json.dumps({"scan_id": "scan-1", "status": "completed", "config": {"target": "example.com"}}))
    routes = {route.path: route.endpoint for route in app.routes if hasattr(route, "endpoint")}
    assert routes["/health"]() == {"status": "ok"}
    try:
        routes["/reports"]()
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401
    else:
        raise AssertionError("unauthenticated dashboard request was accepted")
    authorization = "Bearer readiness-token"
    report_listing = routes["/reports"](authorization)
    assert set(report_listing["reports"]) == {"scan-1/findings.json", "scan-1/scan_state.json"}
    assert report_listing["total"] == 2
    assert routes["/reports/{report_path:path}"]("scan-1/findings.json", authorization)["content"] == []
    assert routes["/scans"](authorization)["scans"][0]["scan_id"] == "scan-1"
    metrics = routes["/metrics"](authorization)
    assert "networkforgeai_" in metrics
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
    required_placeholders = (
        "OPENAI_API_KEY=your_openai_api_key_here",
        "TARGET_SCOPE=",
        "DASHBOARD_AUTH_TOKEN=change_this_secure_random_token",
    )
    checks.append(
        {
            "name": "example configuration is safe and complete",
            "passed": all(value in env_example for value in required_placeholders)
            and "sk-" not in env_example,
        }
    )

    skipped = [str(check["name"]) for check in checks if check.get("skipped")]
    if args.strict:
        checks.append(
            {
                "name": "strict readiness has no skipped checks",
                "passed": not skipped,
                "skipped_checks": skipped,
            }
        )
    names = [str(check.get("name", "")) for check in checks]
    checks.append(
        {
            "name": "readiness report integrity",
            "passed": all(name for name in names) and len(names) == len(set(names)),
        }
    )
    result = {
        "schema_version": 1,
        "mode": "strict" if args.strict else "local",
        "passed": all(bool(check.get("passed")) for check in checks),
        "skipped_checks": skipped,
        "checks": checks,
    }
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
