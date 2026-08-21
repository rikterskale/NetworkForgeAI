"""Notification integrations for findings: Slack (INT-101), Jira (INT-004),
and Microsoft Teams (INT-102).

All integrations share an HTTPS-only JSON transport. Credentials are supplied
explicitly by the operator and never logged; payloads contain sanitized finding
summaries only.
"""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.request import Request, urlopen

from ..reporting.models import prepare_findings

__all__ = [
    "HttpsJsonClient",
    "JiraNotifier",
    "SlackNotifier",
    "TeamsNotifier",
    "summarize_findings",
]

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
_MAX_FINDINGS_IN_MESSAGE = 10


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a sanitized severity summary over normalized findings."""
    rows = prepare_findings(findings)
    counts = {level: 0 for level in _SEVERITY_ORDER}
    for row in rows:
        severity = str(row.get("severity", "informational"))
        if severity in counts:
            counts[severity] += 1
    top = sorted(
        rows,
        key=lambda row: (
            _SEVERITY_ORDER.index(str(row.get("severity", "informational"))),
            str(row.get("type", "")),
        ),
    )[:_MAX_FINDINGS_IN_MESSAGE]
    return {
        "total": len(rows),
        "by_severity": {k: v for k, v in counts.items() if v},
        "top_findings": [
            {
                "type": row.get("type", "unknown"),
                "target": row.get("target", ""),
                "title": row.get("title") or row.get("type", "Untitled"),
                "severity": row.get("severity", "informational"),
            }
            for row in top
        ],
    }


class HttpsJsonClient:
    """HTTPS-only JSON POST transport shared by all notifiers."""

    def __init__(self, endpoint: str, headers: dict[str, str], timeout: float = 10.0):
        if not endpoint.startswith("https://"):
            raise ValueError("Integration endpoint must use HTTPS")
        self.endpoint = endpoint
        self.headers = headers
        self.timeout = timeout

    def post(self, payload: dict[str, Any]) -> int:
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={**self.headers, "Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:  # nosec B310 - endpoint scheme validated in __init__
            return int(response.status)


class SlackNotifier:
    """Post sanitized finding summaries to a Slack incoming webhook."""

    def __init__(self, webhook_url: str, timeout: float = 10.0):
        self.client = HttpsJsonClient(webhook_url, headers={})
        self.timeout = timeout

    def notify_findings(self, findings: list[dict[str, Any]], scan_id: str | None = None) -> int:
        summary = summarize_findings(findings)
        header = "NetworkForgeAI scan completed" + (f" (`{scan_id}`)" if scan_id else "")
        lines = [f"*{header}*", f"Total findings: {summary['total']}"]
        for severity, count in summary["by_severity"].items():
            lines.append(f"• {severity}: {count}")
        blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}
        ]
        details = [
            f"`{item['severity']}` {item['title']} — {item['target']}"
            for item in summary["top_findings"]
        ]
        if details:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "\n".join(details)},
                }
            )
        return self.client.post({"text": header, "blocks": blocks})


class TeamsNotifier:
    """Post sanitized finding summaries to a Microsoft Teams incoming webhook.

    Uses the legacy Office 365 connector message-card schema, which is what
    Teams incoming webhooks accept. The endpoint must use HTTPS.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0):
        self.client = HttpsJsonClient(webhook_url, headers={})
        self.timeout = timeout

    def notify_findings(self, findings: list[dict[str, Any]], scan_id: str | None = None) -> int:
        summary = summarize_findings(findings)
        title = "NetworkForgeAI scan completed" + (f" ({scan_id})" if scan_id else "")
        facts = [{"name": "Total findings", "value": str(summary["total"])}]
        facts += [
            {"name": severity.capitalize(), "value": str(count)}
            for severity, count in summary["by_severity"].items()
        ]
        sections: list[dict[str, Any]] = [
            {
                "activityTitle": title,
                "facts": facts,
                "markdown": True,
            }
        ]
        if summary["top_findings"]:
            details = "\n".join(
                f"- **{item['severity']}** {item['title']} — {item['target']}"
                for item in summary["top_findings"]
            )
            sections.append({"activityTitle": "Top findings", "text": details})
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org",
            "summary": title,
            "themeColor": "C62828" if summary["by_severity"].get("critical") else "36a64f",
            "sections": sections,
        }
        return self.client.post(payload)


class JiraNotifier:
    """Create Jira issues from critical/high findings via the REST API."""

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Task",
        timeout: float = 10.0,
    ):
        if not base_url.startswith("https://"):
            raise ValueError("Jira base_url must use HTTPS")
        if not api_token or api_token.strip() == "":
            raise ValueError("A non-empty Jira API token is required")
        credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        self.project_key = project_key
        self.issue_type = issue_type
        self.timeout = timeout
        endpoint = f"{base_url.rstrip('/')}/rest/api/latest/issue"
        self.client = HttpsJsonClient(
            endpoint,
            headers={"Authorization": f"Basic {credentials}"},
            timeout=timeout,
        )

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        """Open one issue describing a single normalized finding."""
        rows = prepare_findings([finding])
        row = rows[0]
        title = str(row.get("title") or row.get("type") or "NetworkForgeAI finding")
        description = "\n".join(
            filter(
                None,
                [
                    f"Type: {row.get('type', 'unknown')}",
                    f"Target: {row.get('target', '')}",
                    f"Severity: {row.get('severity', 'informational')}",
                    f"Status: {row.get('status', '')}",
                    "",
                    str(row.get("description") or ""),
                    "",
                    f"Remediation: {row.get('remediation') or 'See vendor guidance.'}",
                ],
            )
        )
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[NetworkForgeAI] {title}"[:250],
                "issuetype": {"name": self.issue_type},
                "description": description,
            }
        }
        return self.client.post(payload)
