"""Compliance framework mappings for validated findings.

Maps finding types to OWASP Top 10 (2021), PTES phases, and NIST CSF v1.1
categories so generated reports can cite standard control frameworks.
"""

from __future__ import annotations

from typing import Any

from .models import prepare_findings

# OWASP Top 10 (2021) categories.
OWASP_TOP10: dict[str, str] = {
    "sql_injection": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "command_injection": "A03:2021 - Injection",
    "xxe": "A05:2021 - Security Misconfiguration",
    "broken_access_control": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "path_traversal": "A01:2021 - Broken Access Control",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "weak_crypto": "A02:2021 - Cryptographic Failures",
    "sensitive_data_exposure": "A02:2021 - Cryptographic Failures",
    "tls_weak_cipher": "A02:2021 - Cryptographic Failures",
    "auth_bypass": "A07:2021 - Identification and Authentication Failures",
    "weak_password_policy": "A07:2021 - Identification and Authentication Failures",
    "default_credentials": "A07:2021 - Identification and Authentication Failures",
    "security_misconfiguration": "A05:2021 - Security Misconfiguration",
    "directory_listing": "A05:2021 - Security Misconfiguration",
    "outdated_software": "A06:2021 - Vulnerable and Outdated Components",
    "open_port": "A05:2021 - Security Misconfiguration",
}

# PTES phases (standard section names).
PTES_PHASES: dict[str, str] = {
    "open_port": "Vulnerability Analysis",
    "service_version": "Vulnerability Analysis",
    "os_fingerprint": "Intelligence Gathering",
    "default_credentials": "Exploitation",
    "auth_bypass": "Exploitation",
    "sql_injection": "Exploitation",
    "xss": "Exploitation",
    "password_spray": "Post-Exploitation",
    "privilege_escalation": "Post-Exploitation",
    "lateral_movement": "Post-Exploitation",
}

# NIST CSF v1.1 function -> category mapping for common finding types.
NIST_CSF: dict[str, str] = {
    "sql_injection": "PR.DS - Data Security",
    "xss": "PR.DS - Data Security",
    "ssrf": "PR.AC - Identity Management, Authentication and Access Control",
    "auth_bypass": "PR.AC - Identity Management, Authentication and Access Control",
    "default_credentials": "PR.AC - Identity Management, Authentication and Access Control",
    "weak_password_policy": "PR.AC - Identity Management, Authentication and Access Control",
    "sensitive_data_exposure": "PR.DS - Data Security",
    "weak_crypto": "PR.DS - Data Security",
    "tls_weak_cipher": "PR.PT - Protective Technology",
    "outdated_software": "ID.RM - Risk Management Strategy",
    "security_misconfiguration": "PR.IP - Information Protection Processes and Procedures",
    "open_port": "PR.PT - Protective Technology",
}


def owasp_category(finding_type: str) -> str:
    return OWASP_TOP10.get(finding_type.lower(), "Uncategorized")


def ptes_phase(finding_type: str) -> str:
    return PTES_PHASES.get(finding_type.lower(), "Vulnerability Analysis")


def nist_csf_category(finding_type: str) -> str:
    return NIST_CSF.get(finding_type.lower(), "PR.PT - Protective Technology")


def annotate_compliance(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach OWASP/PTES/NIST metadata to normalized finding dicts in place."""
    for finding in findings:
        finding_type = str(finding.get("type", ""))
        metadata = dict(finding.get("metadata") or {})
        metadata.setdefault("owasp_top10", owasp_category(finding_type))
        metadata.setdefault("ptes_phase", ptes_phase(finding_type))
        metadata.setdefault("nist_csf", nist_csf_category(finding_type))
        finding["metadata"] = metadata
    return findings


def compliance_summary(raw_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return per-framework coverage counts over the given normalized findings."""
    rows = annotate_compliance(prepare_findings(raw_findings or []))
    summary: dict[str, dict[str, int]] = {"owasp_top10": {}, "ptes": {}, "nist_csf": {}}
    keys = {
        "owasp_top10": ("metadata", "owasp_top10"),
        "ptes": ("metadata", "ptes_phase"),
        "nist_csf": ("metadata", "nist_csf"),
    }
    for row in rows:
        metadata = row.get("metadata") or {}
        for name, (_, field) in keys.items():
            value = str(metadata.get(field, "Uncategorized"))
            summary[name][value] = summary[name].get(value, 0) + 1
    return {"finding_count": len(rows), **summary}
