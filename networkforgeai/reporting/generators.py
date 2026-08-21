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


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _pdf_escape(text: str) -> str:
    return (
        str(text)
        .replace("\\", r"\\")
        .replace("(", r"\(")
        .replace(")", r"\)")
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


def _pdf_wrap(text: str, width: int = 92) -> list[str]:
    words = str(text).split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def to_pdf(findings: Iterable[dict[str, Any]]) -> bytes:
    """Render an executive-summary PDF without external dependencies.

    Produces a small, valid single-font PDF document: a title block, severity
    counts, and one wrapped entry per finding sorted by severity.
    """
    rows = prepare_findings(findings)
    counts: dict[str, int] = {}
    for row in rows:
        severity = str(row.get("severity", "informational"))
        counts[severity] = counts.get(severity, 0) + 1
    summary = ", ".join(f"{counts[key]} {key}" for key in sorted(counts)) or "no findings"

    lines: list[str] = [
        "NetworkForgeAI Executive Summary",
        "",
        f"{len(rows)} finding(s): {summary}",
        "",
    ]
    for row in sorted(rows, key=lambda r: _SEVERITY_ORDER.get(str(r.get("severity")), 99)):
        title = row.get("title") or row.get("type") or "finding"
        header = f"[{str(row.get('severity', 'informational')).upper()}] {title}"
        target = row.get("target")
        if target:
            header += f" - {target}"
        lines.append(header)
        description = row.get("description") or ""
        if description:
            lines.extend(f"  {part}" for part in _pdf_wrap(description))
        remediation = row.get("remediation") or ""
        if remediation:
            lines.extend(f"  Remediation: {part}" for part in _pdf_wrap(remediation))
        lines.append("")

    # Body text at 10pt, ~54 lines per page.
    page_size = 54
    pages = [lines[i : i + page_size] for i in range(0, max(len(lines), 1), page_size)]

    page_objects: list[str] = []
    for index, page_lines in enumerate(pages):
        parts: list[str] = ["BT", "/F1 16 Tf", "72 760 Td"]
        for line_no, line in enumerate(page_lines):
            if index == 0 and line_no == 0:
                op = f"({_pdf_escape(line)}) Tj"
            else:
                font_size = "12" if line.startswith("[") else "10"
                op = f"0 -14 Td /F1 {font_size} Tf ({_pdf_escape(line)}) Tj"
            parts.append(op)
        parts.append("ET")
        stream = "\n".join(parts)
        page_objects.append(stream)

    objects: list[str] = []
    n_pages = len(page_objects)
    kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(n_pages))
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")  # obj 1
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>")  # obj 2
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")  # obj 3
    objects.append("<< /Title (NetworkForgeAI Report) /Producer (NetworkForgeAI) >>")  # obj 4
    for i, stream in enumerate(page_objects):
        page_num = 5 + 2 * i
        content_num = page_num + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_num} 0 R >>"
        )
        objects.append(
            f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream"
        )

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{number} 0 obj\n{body}\nendobj\n".encode("latin-1"))
    xref_position = buffer.tell()
    buffer.write(f"xref\n0 {len(objects) + 1}\n".encode())
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets:
        buffer.write(f"{offset:010d} 00000 n \n".encode())
    buffer.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_position}\n%%EOF".encode()
    )
    return buffer.getvalue()
