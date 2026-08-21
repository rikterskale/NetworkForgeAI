"""Validated finding and evidence models used by every report format."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


def _as_utc(value: datetime) -> datetime:
    """Coerce legacy naive timestamps (pre-UTC migration state files) to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    SUSPECTED = "suspected"
    VALIDATED = "validated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"


@dataclass(frozen=True)
class Evidence:
    """Evidence attached to a finding; sensitive evidence is redacted by default."""

    kind: str
    content: str
    source: str = ""
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sensitive: bool = False

    def to_dict(self, redact_sensitive: bool = True) -> dict[str, Any]:
        result = asdict(self)
        result["captured_at"] = self.captured_at.isoformat()
        if redact_sensitive and self.sensitive:
            result["content"] = "[REDACTED]"
        return result


@dataclass
class Finding:
    """Canonical, serializable finding record with stable deduplication identity."""

    type: str
    target: str
    title: str = ""
    severity: Severity = Severity.INFORMATIONAL
    status: FindingStatus = FindingStatus.SUSPECTED
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str | None = None
    owasp: str | None = None
    cvss_score: float | None = None
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.type.strip():
            raise ValueError("Finding type must not be empty")
        if not self.target.strip():
            raise ValueError("Finding target must not be empty")
        self.severity = normalize_severity(self.severity)
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status.lower())
        if self.cvss_score is not None and not 0 <= self.cvss_score <= 10:
            raise ValueError("CVSS score must be between 0 and 10")
        if not self.finding_id:
            self.finding_id = self.identity

    @property
    def identity(self) -> str:
        raw = "|".join((self.type.lower(), self.target.lower(), self.title.lower()))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self, redact_sensitive: bool = True) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        result["status"] = self.status.value
        result["evidence"] = [item.to_dict(redact_sensitive) for item in self.evidence]
        result["created_at"] = self.created_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        values = dict(data)
        evidence = []
        for item in values.pop("evidence", []) or []:
            if isinstance(item, Evidence):
                evidence.append(item)
            else:
                evidence_data = dict(item)
                if isinstance(evidence_data.get("captured_at"), str):
                    evidence_data["captured_at"] = _as_utc(
                        datetime.fromisoformat(evidence_data["captured_at"])
                    )
                evidence.append(Evidence(**evidence_data))
        values["evidence"] = evidence
        if "created_at" not in values and isinstance(values.get("timestamp"), str):
            values["created_at"] = values["timestamp"]
        if isinstance(values.get("created_at"), str):
            values["created_at"] = _as_utc(datetime.fromisoformat(values["created_at"]))
        known = set(cls.__dataclass_fields__)
        extras = {key: values.pop(key) for key in list(values) if key not in known}
        metadata = dict(values.get("metadata") or {})
        metadata.update(extras)
        values["metadata"] = metadata
        return cls(**values)


def normalize_severity(value: Severity | str | None) -> Severity:
    if isinstance(value, Severity):
        return value
    aliases = {"info": "informational", "informative": "informational", "moderate": "medium"}
    normalized = aliases.get(
        str(value or "informational").lower(), str(value or "informational").lower()
    )
    try:
        return Severity(normalized)
    except ValueError:
        return Severity.INFORMATIONAL


def remediation_for(finding_type: str, severity: Severity | str) -> str:
    """Return conservative baseline guidance when a scanner omitted remediation."""
    guidance = {
        "sql_injection": "Use parameterized queries, validate input, and apply least-privilege database access.",
        "xss": "Apply context-aware output encoding, input validation, and a restrictive Content Security Policy.",
        "ssrf": "Allowlist outbound destinations and block private networks and cloud metadata endpoints.",
        "open_port": "Remove unnecessary exposure and restrict access with network controls.",
    }
    return guidance.get(
        finding_type.lower(),
        f"Investigate and remediate the {normalize_severity(severity).value}-risk condition.",
    )


def normalize_finding(value: Finding | dict[str, Any]) -> Finding:
    finding = value if isinstance(value, Finding) else Finding.from_dict(value)
    if not finding.remediation:
        finding.remediation = remediation_for(finding.type, finding.severity)
    return finding


def deduplicate_findings(values: Iterable[Finding | dict[str, Any]]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for value in values:
        finding = normalize_finding(value)
        existing = unique.get(finding.identity)
        if existing is None or _severity_rank(finding.severity) > _severity_rank(existing.severity):
            unique[finding.identity] = finding
    return list(unique.values())


def _severity_rank(value: Severity) -> int:
    return list(Severity).index(value)


def prepare_findings(values: Iterable[Finding | dict[str, Any]]) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in deduplicate_findings(values)]
