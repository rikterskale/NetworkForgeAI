"""Email report delivery over SMTP (RPT-007 / INT-104).

Sends sanitized finding summaries to operator-configured recipients.
STARTTLS is mandatory on non-local submissions; credentials are supplied
explicitly and never logged.
"""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Callable

from .notifications import summarize_findings

__all__ = ["EmailSettings", "SmtpReportSender"]

_SmtpFactory = Callable[[str, int], Any]


@dataclass
class EmailSettings:
    """Operator-supplied SMTP configuration."""

    smtp_host: str
    smtp_port: int = 587
    username: str | None = None
    password: str | None = None
    from_addr: str = "networkforgeai@localhost"
    to_addrs: list[str] = field(default_factory=list)
    require_tls: bool = True

    def __post_init__(self) -> None:
        if not self.smtp_host:
            raise ValueError("smtp_host is required")
        if not self.to_addrs:
            raise ValueError("at least one recipient address is required")


class SmtpReportSender:
    """Deliver scan summaries as RFC-5322 email via SMTP (STARTTLS-first)."""

    def __init__(self, settings: EmailSettings, smtp_factory: _SmtpFactory | None = None):
        self.settings = settings
        self._smtp_factory = smtp_factory or smtplib.SMTP

    def build_message(
        self,
        findings: list[dict[str, Any]],
        scan_id: str | None = None,
        extra_body: str | None = None,
    ) -> EmailMessage:
        summary = summarize_findings(findings)
        subject = "NetworkForgeAI scan report" + (f" ({scan_id})" if scan_id else "")
        lines = [
            subject,
            "",
            f"Total findings: {summary['total']}",
            "",
            "By severity:",
        ]
        for severity, count in summary["by_severity"].items():
            lines.append(f"  - {severity}: {count}")
        lines.extend(["", "Top findings:"])
        for item in summary["top_findings"]:
            lines.append(f"  * [{item['severity']}] {item['title']} — {item['target']}")
        if not summary["top_findings"]:
            lines.append("  (none)")
        if extra_body:
            lines.extend(["", extra_body])
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.settings.from_addr
        message["To"] = ", ".join(self.settings.to_addrs)
        message.set_content("\n".join(lines) + "\n")
        return message

    def send_report(
        self,
        findings: list[dict[str, Any]],
        scan_id: str | None = None,
        extra_body: str | None = None,
    ) -> EmailMessage:
        """Send the summary email; returns the sent message."""
        settings = self.settings
        use_ssl_wrapper = settings.smtp_port == 465
        if use_ssl_wrapper and settings.require_tls:

            def factory(host: str, port: int) -> Any:
                return smtplib.SMTP_SSL(host, port)

            client = factory(settings.smtp_host, settings.smtp_port)
        else:
            client = self._smtp_factory(settings.smtp_host, settings.smtp_port)
        try:
            if settings.require_tls and not use_ssl_wrapper:
                client.starttls()
            if settings.username and settings.password:
                client.login(settings.username, settings.password)
            message = self.build_message(findings, scan_id=scan_id, extra_body=extra_body)
            client.send_message(message)
        finally:
            client.quit()
        return message
