import json

import pytest

from networkforgeai.integrations import WebhookEvent, WebhookNotifier
from networkforgeai.reporting import Severity
from tools.ci_findings_gate import blocking_findings, load_findings


def test_findings_gate_supports_json_and_sarif(tmp_path):
    findings = [
        {"type": "xss", "target": "example.com", "severity": "high"},
        {"type": "old", "target": "example.com", "severity": "critical", "status": "remediated"},
    ]
    json_path = tmp_path / "findings.json"
    json_path.write_text(json.dumps(findings))
    assert len(blocking_findings(load_findings(json_path), Severity.HIGH)) == 1

    sarif_path = tmp_path / "findings.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "sql_injection",
                                "level": "error",
                                "message": {"text": "SQLi"},
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "app"}}}
                                ],
                            }
                        ]
                    }
                ]
            }
        )
    )
    assert load_findings(sarif_path)[0]["target"] == "app"
    with pytest.raises(FileNotFoundError):
        load_findings(tmp_path / "missing.json")


def test_webhook_event_and_explicit_transport(monkeypatch):
    event = WebhookEvent.findings_gate(False, 2)
    assert event.to_dict()["payload"]["blocking_count"] == 2
    with pytest.raises(ValueError):
        WebhookNotifier("http://localhost/hook")
    notifier = WebhookNotifier("http://localhost/hook", allow_http=True)

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    captured = {}

    def fake_urlopen(request, timeout):
        captured["body"] = request.data
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("networkforgeai.integrations.webhooks.urlopen", fake_urlopen)
    assert notifier.send(event) == 202
    assert json.loads(captured["body"])["event_type"] == "findings_gate"
