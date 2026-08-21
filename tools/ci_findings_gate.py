#!/usr/bin/env python3
"""Fail CI when a report contains findings at or above a configured severity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from networkforgeai.reporting import FindingStatus, Severity, normalize_finding

RANK = {severity.value: index for index, severity in enumerate(Severity)}
IGNORED_STATUSES = {FindingStatus.FALSE_POSITIVE.value, FindingStatus.REMEDIATED.value}


def load_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        return [
            {
                "type": result.get("ruleId", "finding"),
                "target": result.get("locations", [{}])[0]
                .get("physicalLocation", {})
                .get("artifactLocation", {})
                .get("uri", "unknown"),
                "description": result.get("message", {}).get("text", ""),
                "severity": {"error": "high", "warning": "medium"}.get(
                    result.get("level", "note"), "informational"
                ),
            }
            for result in data["runs"][0].get("results", [])
        ]
    raise ValueError("Input must be a findings list or SARIF document")


def blocking_findings(findings: list[dict], minimum: Severity) -> list[dict]:
    blocked = []
    for raw in findings:
        finding = normalize_finding(raw)
        if (
            finding.status.value not in IGNORED_STATUSES
            and RANK[finding.severity.value] >= RANK[minimum.value]
        ):
            blocked.append(finding.to_dict())
    return blocked


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply a severity gate to NetworkForgeAI findings")
    parser.add_argument("input", type=Path, help="Findings JSON or SARIF file")
    parser.add_argument(
        "--minimum-severity", choices=[item.value for item in Severity], default="high"
    )
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable result")
    args = parser.parse_args()
    try:
        blocked = blocking_findings(load_findings(args.input), Severity(args.minimum_severity))
        result = {
            "passed": not blocked,
            "minimum_severity": args.minimum_severity,
            "blocking_findings": blocked,
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"passed": False, "error": str(exc), "blocking_findings": []}
    if args.json:
        print(json.dumps(result, indent=2))
    elif result["passed"]:
        print(f"PASS no findings at or above {args.minimum_severity}")
    else:
        print(
            f"FAIL {len(result['blocking_findings'])} finding(s) meet the {args.minimum_severity} gate"
        )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
