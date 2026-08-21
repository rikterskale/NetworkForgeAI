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
    to_pdf,
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


def test_pdf_output_is_valid_and_sorted_by_severity():
    import re

    pdf = to_pdf(
        [
            {"type": "info", "severity": "informational", "title": "Banner", "target": "t.example"},
            {
                "type": "xss",
                "title": "Reflected XSS",
                "severity": "high",
                "target": "app.example",
                "description": "Input is reflected (unescaped) with backslash \\ and parens ().",
                "remediation": "Encode output before rendering.",
            },
        ]
    )
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    # xref offsets must point at their object headers
    xref_pos = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    assert pdf[xref_pos:].startswith(b"xref")
    for number, offset in enumerate(re.findall(rb"(\d{10}) 00000 n", pdf[xref_pos:]), start=1):
        assert pdf[int(offset) :].startswith(f"{number} 0 obj".encode())
    # Escaping kept the payload parseable and severity ordering applied
    body = pdf.decode("latin-1")
    assert "\\(" in body and "\\)" in body  # escaped parens survive
    high_index = body.find("[HIGH]")
    info_index = body.find("[INFORMATIONAL]")
    assert -1 < high_index < info_index
    assert "1 finding(s)" not in body  # summary counts both findings


def test_pdf_handles_empty_input():
    pdf = to_pdf([])
    assert pdf.startswith(b"%PDF-1.4")
    assert b"no findings" in pdf
