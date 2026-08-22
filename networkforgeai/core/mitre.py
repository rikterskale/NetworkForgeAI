"""MITRE ATT&CK technique mapping (ADV-201).

Maps NetworkForgeAI finding types and attack-chain stages to MITRE ATT&CK
(Enterprise) tactics and techniques so reports and attack paths cite a standard
adversary-behaviour taxonomy, the way vendor-grade assessments do.

This module is pure data + lookup. It never executes anything; it only labels
findings that were produced elsewhere. Unknown finding types resolve to an
empty mapping rather than a fabricated technique.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

__all__ = [
    "Technique",
    "techniques_for_type",
    "techniques_for_stage",
    "annotate_finding",
    "coverage_matrix",
]


@dataclass(frozen=True)
class Technique:
    """A single ATT&CK technique reference."""

    technique_id: str
    name: str
    tactic: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.technique_id, "name": self.name, "tactic": self.tactic}


# ---------------------------------------------------------------------------
# Finding-type -> ATT&CK techniques. Keys match the finding ``type`` taxonomy
# already emitted by the agents and tool parsers (see reporting.compliance).
# A finding may map to several techniques across tactics.
# ---------------------------------------------------------------------------
_TYPE_TECHNIQUES: dict[str, tuple[Technique, ...]] = {
    # Reconnaissance / discovery
    "open_port": (Technique("T1046", "Network Service Discovery", "Discovery"),),
    "service_version": (Technique("T1046", "Network Service Discovery", "Discovery"),),
    "host_resolution": (Technique("T1590", "Gather Victim Network Information", "Reconnaissance"),),
    "host_up": (Technique("T1018", "Remote System Discovery", "Discovery"),),
    "subdomain": (Technique("T1590.002", "DNS", "Reconnaissance"),),
    "directory_listing": (Technique("T1083", "File and Directory Discovery", "Discovery"),),
    "technology": (Technique("T1592", "Gather Victim Host Information", "Reconnaissance"),),
    # Web / injection
    "sql_injection": (Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),),
    "xss": (Technique("T1059.007", "JavaScript", "Execution"),),
    "command_injection": (
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        Technique("T1059", "Command and Scripting Interpreter", "Execution"),
    ),
    "ssrf": (Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),),
    "web_vulnerability": (
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ),
    "path_traversal": (Technique("T1083", "File and Directory Discovery", "Discovery"),),
    "xxe": (Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),),
    # API / auth
    "auth_bypass": (Technique("T1078", "Valid Accounts", "Defense Evasion"),),
    "broken_access_control": (
        Technique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    ),
    "idor": (Technique("T1078", "Valid Accounts", "Defense Evasion"),),
    "jwt_alg_none": (
        Technique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    ),
    "jwt_kid_injection": (Technique("T1606", "Forge Web Credentials", "Credential Access"),),
    "jwt_key_injection": (Technique("T1606", "Forge Web Credentials", "Credential Access"),),
    "introspection_enabled": (
        Technique("T1213", "Data from Information Repositories", "Collection"),
    ),
    "ide_exposed": (Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),),
    "verbose_errors": (Technique("T1592", "Gather Victim Host Information", "Reconnaissance"),),
    # Credentials
    "default_credentials": (Technique("T1078.001", "Default Accounts", "Initial Access"),),
    "weak_password_policy": (Technique("T1110", "Brute Force", "Credential Access"),),
    "password_spray": (Technique("T1110.003", "Password Spraying", "Credential Access"),),
    "credential_dump": (Technique("T1003", "OS Credential Dumping", "Credential Access"),),
    # Exploitation / sessions
    "confirmed_vulnerability": (
        Technique("T1203", "Exploitation for Client Execution", "Execution"),
    ),
    "session_opened": (Technique("T1210", "Exploitation of Remote Services", "Lateral Movement"),),
    "remote_code_execution": (
        Technique("T1203", "Exploitation for Client Execution", "Execution"),
    ),
    # Post-exploitation
    "privilege_escalation": (
        Technique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    ),
    "lateral_movement": (Technique("T1021", "Remote Services", "Lateral Movement"),),
    "persistence": (Technique("T1543", "Create or Modify System Process", "Persistence"),),
    "data_exfiltration": (Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),),
    # Cloud / misconfig
    "tls_weak_cipher": (Technique("T1040", "Network Sniffing", "Credential Access"),),
    "security_misconfiguration": (
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ),
    "s3_bucket_public": (Technique("T1530", "Data from Cloud Storage", "Collection"),),
    "cloud_privilege_escalation": (
        Technique("T1078.004", "Cloud Accounts", "Privilege Escalation"),
    ),
}


# ---------------------------------------------------------------------------
# Attack-chain stage -> representative technique. Used when a finding type has
# no direct mapping but its chain stage is known (see core.attack_paths).
# ---------------------------------------------------------------------------
_STAGE_TECHNIQUES: dict[str, Technique] = {
    "recon": Technique("T1595", "Active Scanning", "Reconnaissance"),
    "exposure": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "credential": Technique("T1110", "Brute Force", "Credential Access"),
    "injection": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "misconfiguration": Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "privilege": Technique(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"
    ),
    "lateral": Technique("T1021", "Remote Services", "Lateral Movement"),
}


def techniques_for_type(finding_type: str) -> list[Technique]:
    """Return ATT&CK techniques for a finding type (empty if unknown)."""
    return list(_TYPE_TECHNIQUES.get(finding_type.lower().strip(), ()))


def techniques_for_stage(stage: str) -> list[Technique]:
    """Return the representative technique for an attack-chain stage."""
    technique = _STAGE_TECHNIQUES.get(stage.lower().strip())
    return [technique] if technique else []


def annotate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach an ``attack_techniques`` list to a copy of ``finding``.

    Falls back to the chain stage inferred from the finding type when there is
    no direct type mapping. Never overwrites an existing non-empty mapping.
    """
    enriched = dict(finding)
    if enriched.get("attack_techniques"):
        return enriched
    techniques = techniques_for_type(str(finding.get("type", "")))
    if not techniques:
        # Late import avoids a cycle: attack_paths imports nothing from here.
        from .attack_paths import _stage_of

        techniques = techniques_for_stage(_stage_of(str(finding.get("type", ""))))
    if techniques:
        enriched["attack_techniques"] = [technique.to_dict() for technique in techniques]
    return enriched


def coverage_matrix(findings: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group observed techniques by tactic for an ATT&CK-style coverage table.

    Returns ``{tactic: [{"id", "name", "count"}, ...]}`` sorted for stable
    report rendering. Only techniques actually present in ``findings`` appear.
    """
    counts: dict[tuple[str, str, str], int] = {}
    for finding in findings:
        for technique in annotate_finding(finding).get("attack_techniques", []):
            key = (technique["tactic"], technique["id"], technique["name"])
            counts[key] = counts.get(key, 0) + 1
    matrix: dict[str, list[dict[str, Any]]] = {}
    for (tactic, technique_id, name), count in counts.items():
        matrix.setdefault(tactic, []).append({"id": technique_id, "name": name, "count": count})
    for entries in matrix.values():
        entries.sort(key=lambda item: (item["id"], item["name"]))
    return dict(sorted(matrix.items()))
