"""Provider-neutral outbound integration contracts."""

from .notifications import (
    HttpsJsonClient,
    JiraNotifier,
    SlackNotifier,
    TeamsNotifier,
    summarize_findings,
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
]
