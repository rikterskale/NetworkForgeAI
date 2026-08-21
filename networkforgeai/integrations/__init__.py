"""Provider-neutral outbound integration contracts."""

from .notifications import (
    HttpsJsonClient,
    JiraNotifier,
    SlackNotifier,
    summarize_findings,
)
from .webhooks import WebhookEvent, WebhookNotifier

__all__ = [
    "HttpsJsonClient",
    "JiraNotifier",
    "SlackNotifier",
    "WebhookEvent",
    "WebhookNotifier",
    "summarize_findings",
]
