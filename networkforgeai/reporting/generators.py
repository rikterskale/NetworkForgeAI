"""Small, dependency-light report generators."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Iterable

from .models import prepare_findings


def to_json(findings: Iterable[dict[str, Any]]) -> str:
    return json.dumps(prepare_findings(findings), indent=2, default=str)


def to_csv(findings: Iterable[dict[str, Any]]) -> str:
    rows = prepare_findings(findings)
    keys = sorted({key for row in rows for key in row})
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=keys, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def to_sarif(findings: Iterable[dict[str, Any]]) -> str:
    results = []
    for finding in prepare_findings(findings):
        results.append(
            {
                "ruleId": finding.get("type", "networkforgeai-finding"),
                "level": {"critical": "error", "high": "error", "medium": "warning"}.get(
                    str(finding.get("severity", "note")).lower(), "note"
                ),
                "message": {"text": finding.get("description") or finding.get("summary", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("target", "unknown")}
                        }
                    }
                ],
            }
        )
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "NetworkForgeAI"}}, "results": results}],
        },
        indent=2,
    )
