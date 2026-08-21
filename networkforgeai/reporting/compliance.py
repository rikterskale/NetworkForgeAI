"""Compliance framework mappings for validated findings.

Maps finding types to OWASP Top 10 (2021), PTES phases, NIST CSF v1.1
categories, ISO/IEC 27001:2022 Annex A controls, and PCI-DSS v4 requirements
so generated reports can cite standard control frameworks.
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

# ISO/IEC 27001:2022 Annex A controls for common finding types.
ISO_27001: dict[str, str] = {
    "sql_injection": "A.8.28 - Secure coding",
    "xss": "A.8.28 - Secure coding",
    "command_injection": "A.8.28 - Secure coding",
    "ssrf": "A.8.20 - Networks security",
    "auth_bypass": "A.5.16 - Identity management / A.8.5 - Secure authentication",
    "default_credentials": "A.8.5 - Secure authentication",
    "weak_password_policy": "A.8.5 - Secure authentication",
    "sensitive_data_exposure": "A.8.24 - Use of cryptography",
    "weak_crypto": "A.8.24 - Use of cryptography",
    "tls_weak_cipher": "A.8.24 - Use of cryptography",
    "outdated_software": "A.8.19 - Installation of software on operational systems",
    "security_misconfiguration": "A.8.9 - Configuration management",
    "directory_listing": "A.8.9 - Configuration management",
    "open_port": "A.8.20 - Networks security",
    "idor": "A.8.3 - Information access restriction",
    "path_traversal": "A.8.3 - Information access restriction",
}

# PCI-DSS v4 requirements for common finding types.
PCI_DSS: dict[str, str] = {
    "sql_injection": "Requirement 6.2.4 - Insecure components removed / secure coding",
    "xss": "Requirement 6.2.4 - Insecure components removed / secure coding",
    "command_injection": "Requirement 6.2.4 - Insecure components removed / secure coding",
    "auth_bypass": "Requirement 7 - Restrict access by business need to know",
    "default_credentials": "Requirement 2.2.2 - Vendor defaults removed or changed",
    "weak_password_policy": "Requirement 8.3 - Strong authentication",
    "sensitive_data_exposure": "Requirement 3 - Protect stored account data",
    "weak_crypto": "Requirement 4.2 - Strong cryptography in transit",
    "tls_weak_cipher": "Requirement 4.2.1 - Strong cryptography and protocols",
    "outdated_software": "Requirement 6.3.3 - Critical software patches applied",
    "security_misconfiguration": "Requirement 2.2 - System configuration standards",
    "directory_listing": "Requirement 2.2 - System configuration standards",
    "open_port": "Requirement 1.3 - Restrict inbound traffic to necessary services",
}


def owasp_category(finding_type: str) -> str:
    return OWASP_TOP10.get(finding_type.lower(), "Uncategorized")


def ptes_phase(finding_type: str) -> str:
    return PTES_PHASES.get(finding_type.lower(), "Vulnerability Analysis")


def nist_csf_category(finding_type: str) -> str:
    return NIST_CSF.get(finding_type.lower(), "PR.PT - Protective Technology")


def iso_27001_control(finding_type: str) -> str:
    return ISO_27001.get(finding_type.lower(), "A.8.9 - Configuration management")


def pci_dss_requirement(finding_type: str) -> str:
    return PCI_DSS.get(finding_type.lower(), "Requirement 6.2 - Secure development")


def annotate_compliance(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach OWASP/PTES/NIST/ISO/PCI metadata to normalized finding dicts in place."""
    for finding in findings:
        finding_type = str(finding.get("type", ""))
        metadata = dict(finding.get("metadata") or {})
        metadata.setdefault("owasp_top10", owasp_category(finding_type))
        metadata.setdefault("ptes_phase", ptes_phase(finding_type))
        metadata.setdefault("nist_csf", nist_csf_category(finding_type))
        metadata.setdefault("iso_27001", iso_27001_control(finding_type))
        metadata.setdefault("pci_dss", pci_dss_requirement(finding_type))
        finding["metadata"] = metadata
    return findings


def compliance_summary(raw_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return per-framework coverage counts over the given normalized findings."""
    rows = annotate_compliance(prepare_findings(raw_findings or []))
    summary: dict[str, dict[str, int]] = {
        "owasp_top10": {},
        "ptes": {},
        "nist_csf": {},
        "iso_27001": {},
        "pci_dss": {},
    }
    keys = {
        "owasp_top10": ("metadata", "owasp_top10"),
        "ptes": ("metadata", "ptes_phase"),
        "nist_csf": ("metadata", "nist_csf"),
        "iso_27001": ("metadata", "iso_27001"),
        "pci_dss": ("metadata", "pci_dss"),
    }
    for row in rows:
        metadata = row.get("metadata") or {}
        for name, (_, field) in keys.items():
            value = str(metadata.get(field, "Uncategorized"))
            summary[name][value] = summary[name].get(value, 0) + 1
    return {"finding_count": len(rows), **summary}
