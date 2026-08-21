"""Tests for SIEM forwarding and finding correlation (INT-201/202)."""

import pytest

from networkforgeai.integrations import SplunkHecForwarder, cef_encode, correlate_findings

_FINDING = {
    "type": "sqli",
    "target": "example.com",
    "severity": "high",
    "title": "SQL injection in search",
    "cwe": "CWE-89",
    "description": "Union-based injection",
}


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_cef_encode_renders_single_line():
    event = cef_encode(_FINDING)
    assert "\n" not in event
    assert event.startswith("CEF:0|NetworkForgeAI|scanner|1.0|100|")
    assert "|8|" in event  # high -> CEF severity 8
    assert "target=example.com" in event
    escaped = cef_encode({**_FINDING, "title": "bad=title\nhere"})
    assert "bad\\=title\\nhere" in escaped


def test_splunk_forwarder_json_payload(monkeypatch):
    sent = []

    def fake_post(self, payload):
        sent.append((self.endpoint, self.headers, payload))
        return 200

    from networkforgeai.integrations.notifications import HttpsJsonClient

    monkeypatch.setattr(HttpsJsonClient, "post", fake_post)
    forwarder = SplunkHecForwarder(
        "https://splunk.example.com:8088/services/collector/event",
        token="hec-token",
        index="sec",
    )
    assert forwarder.forward_finding(_FINDING) == 200
    endpoint, headers, payload = sent[0]
    assert "services/collector/event" in endpoint
    assert headers["Authorization"] == "Splunk hec-token"
    assert payload["index"] == "sec"
    assert payload["event"]["type"] == "sqli"
    assert "password" not in str(payload)


def test_splunk_forwarder_cef_mode_and_validation():
    forwarder = SplunkHecForwarder("https://splunk.example.com", token="t", use_cef=True)
    assert isinstance(forwarder.forward_finding.__doc__, str)
    with pytest.raises(ValueError):
        SplunkHecForwarder("http://splunk.example.com", token="t")
    with pytest.raises(ValueError):
        SplunkHecForwarder("https://splunk.example.com", token=" ")


def test_correlate_findings_merges_sources_by_cwe():
    nmap = {"type": "tls_weak_cipher", "target": "example.com", "severity": "low"}
    zap = {
        "type": "sqli",
        "target": "example.com",
        "severity": "high",
        "cwe": "CWE-89",
        "title": "ZAP SQLi",
    }
    burp_like = {
        "type": "sqli",
        "target": "example.com",
        "severity": "medium",
        "cwe": "CWE-89",
        "title": "Manual SQLi",
    }
    records = correlate_findings({"nmap": [nmap], "zap": [zap], "manual": [burp_like]})
    assert len(records) == 2
    by_weakness = {r["weakness"]: r for r in records}
    sqli = by_weakness["CWE-89"]
    assert sqli["sources"] == ["manual", "zap"]
    assert sqli["severity"] == "high"  # highest severity wins
    assert sorted(sqli["titles"]) == ["Manual SQLi", "ZAP SQLi"]
    assert all(len(r["correlation_id"]) == 12 for r in records)


def test_correlate_findings_empty_input():
    assert correlate_findings({}) == []
