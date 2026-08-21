"""Issue-tracker integrations: GitHub (INT-001), GitLab (INT-002),
Linear (INT-005), and generic webhook ticketing (INT-203).

All clients share the HTTPS-only JSON transport and post sanitized finding
data only. Tokens are supplied explicitly by the operator and are never
logged or embedded in payloads.
"""

from __future__ import annotations

import base64
from typing import Any

from ..reporting.models import prepare_findings
from .notifications import HttpsJsonClient

__all__ = [
    "AzureDevOpsWorkItemCreator",
    "BitbucketIssueCreator",
    "GitHubIssueCreator",
    "GitLabIssueCreator",
    "LinearIssueCreator",
    "WebhookTicketClient",
    "finding_to_issue_fields",
]

_DEFAULT_SEVERITIES = {"critical", "high"}

_BITBUCKET_PRIORITY = {
    "critical": "blocker",
    "high": "critical",
    "medium": "major",
    "low": "minor",
    "informational": "trivial",
}


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


class BitbucketIssueCreator:
    """Create Bitbucket Cloud issues for notable findings via REST (INT-003)."""

    def __init__(
        self,
        email: str,
        api_token: str,
        workspace: str,
        repository: str,
        base_url: str = "https://api.bitbucket.org",
        timeout: float = 10.0,
    ):
        if not api_token or api_token.strip() == "":
            raise ValueError("A non-empty Bitbucket app password is required")
        if not base_url.startswith("https://"):
            raise ValueError("Bitbucket base_url must use HTTPS")
        endpoint = f"{base_url.rstrip('/')}/2.0/repositories/{workspace}/{repository}/issues"
        credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        self.client = HttpsJsonClient(
            endpoint,
            headers={"Authorization": f"Basic {credentials}"},
            timeout=timeout,
        )

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        fields = finding_to_issue_fields(finding)
        payload = {
            "title": fields["title"],
            "content": {"raw": fields["body"]},
            "kind": "bug",
            "priority": _BITBUCKET_PRIORITY.get(fields["severity"], "major"),
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


class AzureDevOpsWorkItemCreator:
    """Create Azure DevOps work items for notable findings via REST (INT-006).

    Uses a personal access token (PAT) via Basic auth and the JSON-Patch
    work-item endpoint.
    """

    _WORK_ITEM_TYPES = {
        "critical": "Bug",
        "high": "Bug",
        "medium": "Task",
        "low": "Task",
        "informational": "Task",
    }
    _ADO_PRIORITY = {"critical": "1", "high": "2", "medium": "3", "low": "4", "informational": "4"}

    def __init__(
        self,
        organization: str,
        project: str,
        pat: str,
        base_url: str = "https://dev.azure.com",
        timeout: float = 10.0,
    ):
        if not pat or pat.strip() == "":
            raise ValueError("A non-empty Azure DevOps PAT is required")
        if not base_url.startswith("https://"):
            raise ValueError("Azure DevOps base_url must use HTTPS")
        endpoint = (
            f"{base_url.rstrip('/')}/{organization}/{project}/_apis/wit/wi"
            f"?api-version=7.1&$expand=none"
        )
        credentials = base64.b64encode(f":{pat}".encode()).decode()
        self.client = HttpsJsonClient(
            endpoint,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json-patch+json",
            },
            timeout=timeout,
        )

    def create_issue_for_finding(self, finding: dict[str, Any]) -> int:
        fields = finding_to_issue_fields(finding)
        severity = fields["severity"]
        payload = [
            {"op": "add", "path": "/fields/System.Title", "value": fields["title"]},
            {"op": "add", "path": "/fields/System.Description", "value": fields["body"]},
            {
                "op": "add",
                "path": "/fields/System.WorkItemType",
                "value": self._WORK_ITEM_TYPES.get(severity, "Task"),
            },
            {
                "op": "add",
                "path": "/fields/Microsoft.VSTS.Common.Priority",
                "value": self._ADO_PRIORITY.get(severity, "3"),
            },
        ]
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
