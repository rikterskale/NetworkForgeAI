import json

from networkforgeai.reporting import (
    annotate_compliance,
    compliance_summary,
    iso_27001_control,
    nist_csf_category,
    owasp_category,
    pci_dss_requirement,
    ptes_phase,
    to_html,
)


def test_compliance_mappings_cover_common_types():
    assert owasp_category("sql_injection").startswith("A03")
    assert "Injection" in owasp_category("xss")
    assert ptes_phase("default_credentials") == "Exploitation"
    assert "PR.AC" in nist_csf_category("auth_bypass")
    assert owasp_category("mystery_type") == "Uncategorized"
    assert ptes_phase("mystery_type") == "Vulnerability Analysis"


def test_annotate_and_summary():
    findings = [
        {"type": "sql_injection", "target": "example.com", "severity": "high"},
        {"type": "open_port", "target": "example.com:443", "severity": "low"},
    ]
    annotated = annotate_compliance(findings)
    assert annotated[0]["metadata"]["owasp_top10"].startswith("A03")
    summary = compliance_summary(findings)
    assert summary["finding_count"] == 2
    assert summary["owasp_top10"]["A03:2021 - Injection"] == 1
    assert any(value == 1 for value in summary["ptes"].values())


def test_html_report_escapes_and_summarizes():
    html = to_html(
        [
            {
                "type": "xss",
                "target": "example.com",
                "title": "<script>alert(1)</script>",
                "severity": "high",
            },
            {"type": "open_port", "target": "example.com:22", "severity": "info"},
        ]
    )
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "2 finding(s)" in html
    assert 'class="severity-high"' in html
    assert json.dumps({"ok": True})  # sanity import check


def test_iso27001_and_pci_mappings_and_annotation():
    from networkforgeai.reporting import compliance_summary

    assert "A.8.24" in iso_27001_control("weak_crypto")
    assert "Requirement 2.2.2" in pci_dss_requirement("default_credentials")
    # Unknown types fall back to sensible defaults rather than raising
    assert "Configuration management" in iso_27001_control("brand_new_type")
    assert "Secure development" in pci_dss_requirement("brand_new_type")

    rows = annotate_compliance(
        [{"type": "sql_injection", "target": "db.example", "severity": "critical"}]
    )
    meta = rows[0]["metadata"]
    assert "A.8.28" in meta["iso_27001"]
    assert "6.2.4" in meta["pci_dss"]
    summary = compliance_summary(
        [{"type": "tls_weak_cipher", "target": "t.example", "severity": "medium"}]
    )
    assert summary["iso_27001"]["A.8.24 - Use of cryptography"] == 1
    assert summary["pci_dss"]["Requirement 4.2.1 - Strong cryptography and protocols"] == 1
