"""Small, dependency-light report generators."""

from __future__ import annotations

import csv
import html
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


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetworkForgeAI Report</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.4rem; text-align: left; vertical-align: top; }}
th {{ background: #f4f4f4; }}
tr.severity-critical td:first-child {{ border-left: 6px solid #a00; }}
tr.severity-high td:first-child {{ border-left: 6px solid #c50; }}
tr.severity-medium td:first-child {{ border-left: 6px solid #da0; }}
tr.severity-low td:first-child {{ border-left: 6px solid #aa0; }}
tr.severity-informational td:first-child {{ border-left: 6px solid #888; }}
</style>
</head>
<body>
<h1>NetworkForgeAI Findings Report</h1>
<p>{count} finding(s), {summary}</p>
<table>
<thead><tr><th>Severity</th><th>Type</th><th>Target</th><th>Title</th><th>Status</th><th>Description</th><th>Remediation</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def to_html(findings: Iterable[dict[str, Any]]) -> str:
    rows = prepare_findings(findings)
    counts: dict[str, int] = {}
    for row in rows:
        severity = str(row.get("severity", "informational"))
        counts[severity] = counts.get(severity, 0) + 1
    summary = ", ".join(f"{counts[key]} {key}" for key in sorted(counts)) or "no findings"
    rendered = []
    for row in rows:
        cells = "".join(
            f"<td>{html.escape(str(row.get(key, '') or ''))}</td>"
            for key in (
                "severity",
                "type",
                "target",
                "title",
                "status",
                "description",
                "remediation",
            )
        )
        rendered.append(
            f'<tr class="severity-{html.escape(str(row.get("severity", "informational")))}">{cells}</tr>'
        )
    return _HTML_TEMPLATE.format(
        count=len(rows), summary=html.escape(summary), rows="\n".join(rendered)
    )
