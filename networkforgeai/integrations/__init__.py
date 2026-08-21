"""Provider-neutral outbound integration contracts."""

from .email_delivery import EmailSettings, SmtpReportSender
from .notifications import (
    HttpsJsonClient,
    JiraNotifier,
    SlackNotifier,
    TeamsNotifier,
    summarize_findings,
)
from .siem import SplunkHecForwarder, cef_encode, correlate_findings
from .trackers import (
    GitHubIssueCreator,
    GitLabIssueCreator,
    LinearIssueCreator,
    WebhookTicketClient,
    finding_to_issue_fields,
    select_notable_findings,
)
from .webhooks import WebhookEvent, WebhookNotifier

__all__ = [
    "HttpsJsonClient",
    "JiraNotifier",
    "SlackNotifier",
    "TeamsNotifier",
    "WebhookEvent",
    "WebhookNotifier",
    "summarize_findings",
    "GitHubIssueCreator",
    "GitLabIssueCreator",
    "LinearIssueCreator",
    "WebhookTicketClient",
    "finding_to_issue_fields",
    "select_notable_findings",
    "EmailSettings",
    "SmtpReportSender",
    "SplunkHecForwarder",
    "cef_encode",
    "correlate_findings",
]
