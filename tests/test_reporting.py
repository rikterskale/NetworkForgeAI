import json

from networkforgeai.reporting import to_csv, to_json, to_sarif


def test_report_formats_are_serializable():
    findings = [{"type": "open_port", "target": "example.com", "severity": "Informational"}]
    assert json.loads(to_json(findings))[0]["type"] == "open_port"
    assert "target" in to_csv(findings)
    assert json.loads(to_sarif(findings))["version"] == "2.1.0"

