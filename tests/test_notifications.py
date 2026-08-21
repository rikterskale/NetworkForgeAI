import base64
import json

import pytest

from networkforgeai.integrations import (
    JiraNotifier,
    SlackNotifier,
    WebhookNotifier,
    summarize_findings,
)


@pytest.fixture()
def capture(monkeypatch):
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["body"] = request.data
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("networkforgeai.integrations.notifications.urlopen", fake_urlopen)
    return captured


FINDINGS = [
    {"type": "sql_injection", "target": "example.com/login", "severity": "critical"},
    {"type": "open_port", "target": "example.com:22", "severity": "low"},
]


def test_summarize_findings_orders_and_sanitizes():
    summary = summarize_findings(FINDINGS)
    assert summary["total"] == 2
    assert summary["by_severity"] == {"critical": 1, "low": 1}
    assert summary["top_findings"][0]["severity"] == "critical"
    assert set(summary["top_findings"][0]) == {"type", "target", "title", "severity"}


def test_slack_notifier_posts_blocks_and_enforces_https(capture):
    with pytest.raises(ValueError):
        SlackNotifier("http://hooks.slack.invalid/services/T000/B000/xyz")
    notifier = SlackNotifier("https://hooks.slack.invalid/services/T000/B000/xyz")
    status = notifier.notify_findings(FINDINGS, scan_id="scan-123")
    assert status == 200
    payload = json.loads(capture["body"])
    assert "scan-123" in payload["text"]
    assert any("Total findings: 2" in b["text"]["text"] for b in payload["blocks"])
    assert any("`critical`" in b.get("text", {}).get("text", "") for b in payload["blocks"])


def test_jira_notifier_builds_issue_payload_and_auth(capture):
    base = "https://jira.example.invalid"
    with pytest.raises(ValueError):
        JiraNotifier(base + "/rest", "ops@example.com", "", "SEC")
    notifier = JiraNotifier(base, "ops@example.com", "token-123", "SEC")
    status = notifier.create_issue_for_finding(FINDINGS[0])
    assert status == 200
    assert capture["url"] == base + "/rest/api/latest/issue"
    auth = capture["headers"].get("Authorization", "")
    assert auth.startswith("Basic ")
    decoded = base64.b64decode(auth.split()[1]).decode()
    assert decoded == "ops@example.com:token-123"
    fields = json.loads(capture["body"])["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert fields["summary"].startswith("[NetworkForgeAI] ")
    assert "Target: example.com/login" in fields["description"]
    assert fields["description"].rstrip() != "" and "Remediation:" in fields["description"]


def test_webhook_notifier_still_https_only():
    with pytest.raises(ValueError):
        WebhookNotifier("http://localhost/hook")


def test_teams_notifier_posts_message_card_and_enforces_https(capture):
    from networkforgeai.integrations import TeamsNotifier

    with pytest.raises(ValueError):
        TeamsNotifier("http://outlook.office.invalid/webhook/xyz")
    notifier = TeamsNotifier("https://outlook.office.invalid/webhook/abc/xyz")
    status = notifier.notify_findings(FINDINGS, scan_id="scan-123")
    assert status == 200
    payload = json.loads(capture["body"])
    assert payload["@type"] == "MessageCard"
    assert payload["summary"].startswith("NetworkForgeAI scan completed")
    assert "scan-123" in payload["summary"]
    # Critical findings drive the red theme color
    assert payload["themeColor"] == "C62828"
    facts = {f["name"]: f["value"] for f in payload["sections"][0]["facts"]}
    assert facts == {"Total findings": "2", "Critical": "1", "Low": "1"}
    assert any("Top findings" in s.get("activityTitle", "") for s in payload["sections"])
