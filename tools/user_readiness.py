#!/usr/bin/env python3
"""Production user-readiness gate for local and CI execution."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(name: str, command: list[str], checks: list[dict[str, object]]) -> None:
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
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

    run("python compilation", [python, "-m", "compileall", "-q", "networkforgeai", "tests"], checks)
    run("CLI help", [python, "-m", "networkforgeai.cli", "--help"], checks)
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
    run("documentation audit", [python, "tools/ci_docs_audit.py"], checks)
    report_script = (
        "from networkforgeai.reporting import to_csv, to_json, to_sarif; "
        "f=[{'type':'readiness','target':'example.com'}]; "
        "assert 'readiness' in to_json(f); assert 'target' in to_csv(f); "
        "assert '2.1.0' in to_sarif(f)"
    )
    run("report format generation", [python, "-c", report_script], checks)

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
