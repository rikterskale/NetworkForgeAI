"""Provider-neutral outbound integration contracts."""

from .email_delivery import EmailSettings, SmtpReportSender
from .notifications import (
    DiscordNotifier,
    HttpsJsonClient,
    JiraNotifier,
    SlackNotifier,
    TeamsNotifier,
    summarize_findings,
)
from .secrets import SecretRef, SecretResolver
from .siem import SplunkHecForwarder, cef_encode, correlate_findings
from .trackers import (
    AzureDevOpsWorkItemCreator,
    BitbucketIssueCreator,
    GitHubIssueCreator,
    GitLabIssueCreator,
    LinearIssueCreator,
    WebhookTicketClient,
    finding_to_issue_fields,
    select_notable_findings,
)
from .webhooks import WebhookEvent, WebhookNotifier

__all__ = [
    "DiscordNotifier",
    "HttpsJsonClient",
    "JiraNotifier",
    "SlackNotifier",
    "TeamsNotifier",
    "WebhookEvent",
    "WebhookNotifier",
    "summarize_findings",
    "AzureDevOpsWorkItemCreator",
    "BitbucketIssueCreator",
    "GitHubIssueCreator",
    "GitLabIssueCreator",
    "LinearIssueCreator",
    "WebhookTicketClient",
    "finding_to_issue_fields",
    "select_notable_findings",
    "EmailSettings",
    "SmtpReportSender",
    "SecretRef",
    "SecretResolver",
    "SplunkHecForwarder",
    "cef_encode",
    "correlate_findings",
]
