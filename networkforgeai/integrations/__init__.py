"""Provider-neutral outbound integration contracts."""

from .webhooks import WebhookEvent, WebhookNotifier

__all__ = ["WebhookEvent", "WebhookNotifier"]
