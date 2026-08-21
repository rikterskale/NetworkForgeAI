"""Tests for issue-tracker integrations and email delivery."""

import pytest

from networkforgeai.integrations import (
    EmailSettings,
    GitHubIssueCreator,
    GitLabIssueCreator,
    LinearIssueCreator,
    SmtpReportSender,
    WebhookTicketClient,
    finding_to_issue_fields,
    select_notable_findings,
)

_FINDING = {
    "type": "sqli",
    "target": "example.com",
    "severity": "high",
    "title": "SQL injection in search",
    "description": "Union-based injection",
    "remediation": "Use parameterized queries",
}

_LOW_FINDING = {"type": "info_page", "target": "example.com", "severity": "informational"}


class FakeResponse:
    def __init__(self, status=201):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def capture(monkeypatch):
    """Capture HttpsJsonClient.post payloads."""
    sent: list[tuple[str, dict, dict]] = []

    def fake_post(self, payload):
        sent.append((self.endpoint, self.headers, payload))
        return 201

    from networkforgeai.integrations.notifications import HttpsJsonClient

    monkeypatch.setattr(HttpsJsonClient, "post", fake_post)
    return sent


def test_finding_to_issue_fields_sanitizes():
    fields = finding_to_issue_fields({**_FINDING, "password": "hunter2"})
    assert fields["title"].startswith("[NetworkForgeAI]")
    assert "Union-based injection" in fields["body"]
    assert "Use parameterized queries" in fields["body"]
    assert "hunter2" not in str(fields)


def test_select_notable_findings_filters_severity():
    notable = select_notable_findings([_FINDING, _LOW_FINDING])
    assert len(notable) == 1
    all_rows = select_notable_findings(
        [_FINDING, _LOW_FINDING], min_severity={"informational", "high"}
    )
    assert len(all_rows) == 2


def test_github_issue_creator(capture):
    creator = GitHubIssueCreator(token="tok", owner="acme", repo="findings")
    status = creator.create_issue_for_finding(_FINDING)
    assert status == 201
    endpoint, headers, payload = capture[0]
    assert endpoint == "https://api.github.com/repos/acme/findings/issues"
    assert headers["Authorization"] == "Bearer tok"
    assert payload["labels"] == ["security", "high"]
    assert payload["title"].startswith("[NetworkForgeAI]")


def test_github_rejects_empty_token_and_http_base():
    with pytest.raises(ValueError):
        GitHubIssueCreator(token=" ", owner="a", repo="b")
    with pytest.raises(ValueError):
        GitHubIssueCreator(token="t", owner="a", repo="b", base_url="http://api.github.com")


def test_gitlab_issue_creator(capture):
    creator = GitLabIssueCreator(token="gl-tok", project_id="42")
    assert creator.create_issue_for_finding(_FINDING) == 201
    endpoint, headers, payload = capture[0]
    assert endpoint == "https://gitlab.com/api/v4/projects/42/issues"
    assert headers["PRIVATE-TOKEN"] == "gl-tok"
    assert "security" in payload["labels"]
    with pytest.raises(ValueError):
        GitLabIssueCreator(token="", project_id="42")


def test_linear_issue_creator(capture):
    creator = LinearIssueCreator(api_key="lin-key", team_id="team-1")
    assert creator.create_issue_for_finding(_FINDING) == 201
    _, headers, payload = capture[0]
    assert headers["Authorization"] == "lin-key"
    variables = payload["variables"]["input"]
    assert variables["teamId"] == "team-1"
    assert payload["query"].startswith("mutation IssueCreate")
    with pytest.raises(ValueError):
        LinearIssueCreator(api_key="", team_id="t")


def test_webhook_ticket_client(capture):
    client = WebhookTicketClient(
        "https://tickets.example.com/hooks/nfa", headers={"X-Auth": "secret"}
    )
    assert client.create_issue_for_finding(_FINDING) == 201
    endpoint, headers, payload = capture[0]
    assert endpoint == "https://tickets.example.com/hooks/nfa"
    assert headers["X-Auth"] == "secret"
    assert payload["severity"] == "high"


def test_bitbucket_issue_creator(capture):
    from networkforgeai.integrations import BitbucketIssueCreator

    creator = BitbucketIssueCreator(
        email="ops@example.com", api_token="app-password", workspace="acme", repository="findings"
    )
    assert creator.create_issue_for_finding(_FINDING) == 201
    endpoint, headers, payload = capture[0]
    assert endpoint == "https://api.bitbucket.org/2.0/repositories/acme/findings/issues"
    assert headers["Authorization"].startswith("Basic ")
    assert payload["priority"] == "critical"  # high -> critical
    assert payload["kind"] == "bug"
    with pytest.raises(ValueError):
        BitbucketIssueCreator(email="e", api_token="", workspace="w", repository="r")


def test_email_settings_validation():
    with pytest.raises(ValueError):
        EmailSettings(smtp_host="")
    with pytest.raises(ValueError):
        EmailSettings(smtp_host="smtp.example.com", to_addrs=[])


def test_email_build_message():
    settings = EmailSettings(
        smtp_host="smtp.example.com", to_addrs=["soc@example.com"], from_addr="nfa@example.com"
    )
    sender = SmtpReportSender(settings)
    message = sender.build_message([_FINDING], scan_id="scan-9")
    assert message["Subject"] == "NetworkForgeAI scan report (scan-9)"
    assert message["To"] == "soc@example.com"
    body = message.get_content()
    assert "Total findings: 1" in body and "SQL injection" in body


def _make_fake_smtp(record):
    class FakeSMTP:
        def __init__(self, host, port):
            record.append(("connect", host, port))

        def starttls(self):
            record.append(("starttls",))

        def login(self, user, password):
            record.append(("login", user))

        def send_message(self, message):
            record.append(("send", message["Subject"]))

        def quit(self):
            record.append(("quit",))

    return FakeSMTP


def test_email_send_report_with_tls_and_login():
    record: list[tuple] = []
    settings = EmailSettings(
        smtp_host="smtp.example.com",
        username="svc",
        password="pw-secret",
        to_addrs=["soc@example.com"],
    )
    sender = SmtpReportSender(settings, smtp_factory=_make_fake_smtp(record))
    sender.send_report([_FINDING])
    steps = [entry[0] for entry in record]
    assert steps == ["connect", "starttls", "login", "send", "quit"]
    assert "pw-secret" not in str(record)


def test_email_send_report_ssl_port_uses_ssl_wrapper():
    calls: list[str] = []

    class FakeSSL:
        def __init__(self, host, port):
            calls.append("ssl")

        def send_message(self, message):
            pass

        def quit(self):
            pass

    settings = EmailSettings(
        smtp_host="smtp.example.com", smtp_port=465, to_addrs=["soc@example.com"]
    )
    sender = SmtpReportSender(settings)
    sender._smtp_factory = None  # ensure factory path is not used
    import networkforgeai.integrations.email_delivery as module

    original = module.smtplib.SMTP_SSL
    module.smtplib.SMTP_SSL = FakeSSL
    try:
        message = sender.send_report([_FINDING])
        assert message["Subject"].startswith("NetworkForgeAI")
    finally:
        module.smtplib.SMTP_SSL = original
    assert calls == ["ssl"]
