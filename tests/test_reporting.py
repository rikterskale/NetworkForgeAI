import json

import pytest

from networkforgeai.reporting import (
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    deduplicate_findings,
    normalize_finding,
    remediation_for,
    to_csv,
    to_json,
    to_sarif,
)


def test_report_formats_are_serializable():
    findings = [{"type": "open_port", "target": "example.com", "severity": "Informational"}]
    assert json.loads(to_json(findings))[0]["type"] == "open_port"
    assert "target" in to_csv(findings)
    assert json.loads(to_sarif(findings))["version"] == "2.1.0"


def test_finding_model_validates_normalizes_and_redacts():
    evidence = Evidence("log", "Authorization: Bearer secret", "proxy", sensitive=True)
    finding = Finding(
        type="sql_injection",
        target="example.com/login",
        title="SQL Injection",
        severity="critical",
        status="validated",
        evidence=[evidence],
        cvss_score=9.8,
    )
    assert finding.severity is Severity.CRITICAL
    assert finding.status is FindingStatus.VALIDATED
    assert finding.finding_id == finding.identity
    assert finding.to_dict()["evidence"][0]["content"] == "[REDACTED]"
    assert finding.to_dict(redact_sensitive=False)["evidence"][0]["content"].endswith("secret")
    restored = Finding.from_dict(finding.to_dict(redact_sensitive=False))
    assert restored.evidence[0].captured_at == evidence.captured_at
    with pytest.raises(ValueError):
        Finding(type="", target="example.com")
    with pytest.raises(ValueError):
        Finding(type="x", target="", cvss_score=11)


def test_finding_normalization_deduplication_and_remediation():
    duplicate_low = {
        "type": "open_port",
        "target": "EXAMPLE.COM",
        "title": "Port",
        "severity": "info",
    }
    duplicate_high = {
        "type": "open_port",
        "target": "example.com",
        "title": "Port",
        "severity": "high",
    }
    normalized = normalize_finding(duplicate_low)
    assert normalized.severity is Severity.INFORMATIONAL
    assert normalized.remediation
    deduplicated = deduplicate_findings([duplicate_low, duplicate_high])
    assert len(deduplicated) == 1
    assert deduplicated[0].severity is Severity.HIGH
    assert remediation_for("unknown", "medium").startswith("Investigate")
    assert remediation_for("xss", "high").startswith("Apply")


def test_report_generators_normalize_and_deduplicate():
    findings = [
        {"type": "xss", "target": "example.com", "title": "XSS", "severity": "high"},
        {"type": "xss", "target": "example.com", "title": "XSS", "severity": "low"},
    ]
    payload = json.loads(to_json(findings))
    assert len(payload) == 1
    assert payload[0]["remediation"]
    assert "redacted" not in to_csv(findings).lower()
    sarif = json.loads(to_sarif(findings))
    assert len(sarif["runs"][0]["results"]) == 1
