"""Issue-tracker integrations: GitHub (INT-001), GitLab (INT-002),
Linear (INT-005), and generic webhook ticketing (INT-203).

All clients share the HTTPS-only JSON transport and post sanitized finding
data only. Tokens are supplied explicitly by the operator and are never
logged or embedded in payloads.
"""

from __future__ import annotations

from typing import Any

from ..reporting.models import prepare_findings
from .notifications import HttpsJsonClient

__all__ = [
    "GitHubIssueCreator",
    "GitLabIssueCreator",
    "LinearIssueCreator",
    "WebhookTicketClient",
    "finding_to_issue_fields",
]

_DEFAULT_SEVERITIES = {"critical", "high"}


def finding_to_issue_fields(finding: dict[str, Any]) -> dict[str, str]:
    """Build a sanitized title/body pair from one normalized finding."""
    row = prepare_findings([finding])[0]
    title = str(row.get("title") or row.get("type") or "NetworkForgeAI finding")
    severity = str(row.get("severity", "informational"))
    lines = [
        f"Type: {row.get('type', 'unknown')}",
        f"Target: {row.get('target', '')}",
        f"Severity: {severity}",
        "",
        str(row.get("description") or ""),
        "",
        f"Remediation: {row.get('remediation') or 'See vendor guidance.'}",
    ]
    return {
        "title": f"[NetworkForgeAI] {title}"[:250],
        "body": "\n".join(lines),
        "severity": severity,
    }


def select_notable_findings(
    findings: list[dict[str, Any]],
    min_severity: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Return normalized findings at or above the configured severities."""
    allowed = min_severity or _DEFAULT_SEVERITIES
    rows = prepare_findings(findings)
    return [row for row in rows if str(row.get("severity", "informational")) in allowed]


class GitHubIssueCreator:
    """Create GitHub issues for notable findings via the REST API (INT-001)."""

    def __init__(
        self,
        token: str,
        owner: str,
        repo: str,
        base_url: str = "https://api.github.com",
        labels: list[str] | None = None,
        timeout: float = 10.0,
    ):
        if not token or token.strip() == "":
            raise ValueError("A non-empty GitHub token is required")
        if not base_url.startswith("https://"):
            raise ValueError("GitHub base_url must use HTTPS")
        endpoint = f"{base_url.rstrip('/')}/repos/{owner}/{repo}/issues"
        self.labels = labels or ["security"]
        self.client = HttpsJsonClient(
            endpoint,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=timeout,
        )

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        fields = finding_to_issue_fields(finding)
        payload: dict[str, Any] = {
            "title": fields["title"],
            "body": fields["body"],
            "labels": [*self.labels, fields["severity"]],
        }
        return self.client.post(payload)


class GitLabIssueCreator:
    """Create GitLab issues for notable findings via the REST API (INT-002)."""

    def __init__(
        self,
        token: str,
        project_id: str,
        base_url: str = "https://gitlab.com",
        labels: list[str] | None = None,
        timeout: float = 10.0,
    ):
        if not token or token.strip() == "":
            raise ValueError("A non-empty GitLab token is required")
        if not base_url.startswith("https://"):
            raise ValueError("GitLab base_url must use HTTPS")
        endpoint = f"{base_url.rstrip('/')}/api/v4/projects/{project_id}/issues"
        self.labels = labels or ["security"]
        self.client = HttpsJsonClient(
            endpoint,
            headers={"PRIVATE-TOKEN": token},
            timeout=timeout,
        )

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        fields = finding_to_issue_fields(finding)
        payload = {
            "title": fields["title"],
            "description": fields["body"],
            "labels": ",".join([*self.labels, fields["severity"]]),
        }
        return self.client.post(payload)


class LinearIssueCreator:
    """Create Linear issues for notable findings via GraphQL (INT-005)."""

    def __init__(
        self,
        api_key: str,
        team_id: str,
        timeout: float = 10.0,
    ):
        if not api_key or api_key.strip() == "":
            raise ValueError("A non-empty Linear API key is required")
        self.team_id = team_id
        self.client = HttpsJsonClient(
            "https://api.linear.app/graphql",
            headers={"Authorization": api_key},
            timeout=timeout,
        )

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        fields = finding_to_issue_fields(finding)
        mutation = (
            "mutation IssueCreate($input: IssueCreateInput!) {"
            " issueCreate(input: $input) { issue { id } } }"
        )
        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "teamId": self.team_id,
                    "title": fields["title"],
                    "description": fields["body"],
                }
            },
        }
        return self.client.post(payload)


class WebhookTicketClient:
    """Create tickets in arbitrary systems via a generic JSON webhook (INT-203)."""

    def __init__(
        self,
        endpoint: str,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ):
        self.client = HttpsJsonClient(endpoint, headers=headers or {}, timeout=timeout)

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        fields = finding_to_issue_fields(finding)
        payload = {
            "subject": fields["title"],
            "body": fields["body"],
            "severity": fields["severity"],
        }
        return self.client.post(payload)
