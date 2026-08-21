"""Finding validation engine: CVSS scoring, advisory PoC generation,
false-positive elimination, and business-impact assessment.

All output is advisory. Nothing here executes offensive actions; every PoC is
a suggestion that still passes through the human approval gateway.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..reporting.models import Finding, FindingStatus, Severity, normalize_severity

__all__ = [
    "ImpactAssessment",
    "PoCSuggestion",
    "ValidationVerdict",
    "assess_impact",
    "cvss_base_score",
    "cvss_for_severity",
    "eliminate_false_positives",
    "generate_poc",
]


# ---------------------------------------------------------------------------
# VAL-004: CVSS calculator (CVSS v3.1 base score)
# ---------------------------------------------------------------------------

_CVSS_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_UNCHANGED": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_CHANGED": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_SEVERITY_CVSS: dict[Severity, float] = {
    Severity.INFORMATIONAL: 0.0,
    Severity.LOW: 3.9,
    Severity.MEDIUM: 6.5,
    Severity.HIGH: 8.5,
    Severity.CRITICAL: 9.8,
}


def cvss_for_severity(severity: Severity | str | None) -> float:
    """Return the conservative baseline CVSS score for a severity level."""
    return _SEVERITY_CVSS[normalize_severity(severity)]


def cvss_base_score(vector: str) -> float:
    """Compute a CVSS v3.1 base score from a base-metric vector string."""
    parts = dict(
        piece.split(":", 1)
        for piece in vector.upper().replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
        if ":" in piece
    )
    missing = [key for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A") if key not in parts]
    if missing:
        raise ValueError(f"Vector missing base metrics: {', '.join(missing)}")
    scope_changed = parts["S"] == "C"
    exploitability = (
        8.22
        * _CVSS_WEIGHTS["AV"][parts["AV"]]
        * _CVSS_WEIGHTS["AC"][parts["AC"]]
        * (_CVSS_WEIGHTS["PR_CHANGED"] if scope_changed else _CVSS_WEIGHTS["PR_UNCHANGED"])[
            parts["PR"]
        ]
        * _CVSS_WEIGHTS["UI"][parts["UI"]]
    )
    impact_sub = 1 - (1 - _CVSS_WEIGHTS["C"][parts["C"]]) * (1 - _CVSS_WEIGHTS["I"][parts["I"]]) * (
        1 - _CVSS_WEIGHTS["A"][parts["A"]]
    )
    impact = (
        6.42 * impact_sub
        if not scope_changed
        else 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    )
    if impact <= 0:
        return 0.0
    score = min(impact + exploitability, 10.0)
    return math.ceil(score * 10) / 10


# ---------------------------------------------------------------------------
# VAL-001: Advisory PoC generator
# ---------------------------------------------------------------------------

_POC_TEMPLATES: dict[str, list[str]] = {
    "sql_injection": [
        "# Verify parameterized handling manually before any active test.",
        "sqlmap -u {target} --batch --level=1 --risk=1",
    ],
    "xss": [
        "# Reflect a benign marker and inspect the response encoding.",
        'curl -sG "{target}" --data-urlencode "q=<script>nfai</script>"',
    ],
    "open_port": ["nmap -sV -p {port} {target}"],
    "ssrf": [
        "# Point the parameter at a host you control and confirm the callback.",
        'curl "{target}?url=http://{callback_host}/probe"',
    ],
}


@dataclass(frozen=True)
class PoCSuggestion:
    """Advisory proof-of-concept steps; never executed by this framework."""

    finding_id: str
    finding_type: str
    description: str
    commands: list[str]
    requires_human_approval: bool = True
    notes: str = ""


def generate_poc(
    finding: Finding, callback_host: str = "callback.example.invalid"
) -> PoCSuggestion:
    """Build an advisory PoC suggestion for a validated-or-suspected finding."""
    context = {
        "target": finding.target,
        "port": str(finding.metadata.get("port", "80")),
        "callback_host": callback_host,
    }
    commands = [
        command.format(**context) for command in _POC_TEMPLATES.get(finding.type.lower(), [])
    ]
    if not commands:
        commands = [f"# Manually verify {finding.type} on {finding.target}; no template available."]
    return PoCSuggestion(
        finding_id=finding.finding_id,
        finding_type=finding.type,
        description=f"Manual verification steps for {finding.title or finding.type} on {finding.target}",
        commands=commands,
        notes="Advisory only. Any active command requires explicit human approval and scope validation.",
    )


# ---------------------------------------------------------------------------
# VAL-003: False-positive eliminator
# ---------------------------------------------------------------------------

_FP_SIGNATURES: tuple[str, ...] = (
    "honeypot",
    "test.example",
    "example.invalid",
)


@dataclass(frozen=True)
class ValidationVerdict:
    finding_id: str
    status: FindingStatus
    confidence: float
    reasons: list[str] = field(default_factory=list)

    @property
    def corroborated(self) -> bool:
        return self.status is FindingStatus.VALIDATED


def eliminate_false_positives(findings: list[Finding]) -> list[ValidationVerdict]:
    """Score each finding with multi-signal heuristics and suggest a status.

    Signals: number of independent evidence items, sensitive/redacted content
    presence, known false-positive signatures, and whether remediation guidance
    exists. Output is advisory; statuses are suggestions, not mutations.
    """
    verdicts: list[ValidationVerdict] = []
    for finding in findings:
        reasons: list[str] = []
        confidence = 0.3
        evidence_count = len(finding.evidence)
        if evidence_count >= 2:
            confidence += 0.25 * min(evidence_count - 1, 2)
            reasons.append(f"{evidence_count} independent evidence items")
        elif evidence_count == 1:
            confidence += 0.1
            reasons.append("single evidence item")
        else:
            reasons.append("no evidence attached")
        blob = (
            " ".join(item.content.lower() for item in finding.evidence)
            + " "
            + finding.target.lower()
        )
        hits = [signature for signature in _FP_SIGNATURES if signature in blob]
        if hits:
            confidence -= 0.4
            reasons.append(f"false-positive signature present: {', '.join(hits)}")
        if finding.status is FindingStatus.VALIDATED:
            confidence += 0.2
            reasons.append("previously marked validated")
        if normalize_severity(finding.severity) is Severity.INFORMATIONAL and evidence_count == 0:
            confidence -= 0.15
        confidence = max(0.0, min(1.0, round(confidence, 2)))
        if hits:
            suggested = FindingStatus.FALSE_POSITIVE
        elif evidence_count >= 1 and confidence >= 0.5:
            suggested = FindingStatus.VALIDATED
        else:
            suggested = FindingStatus.SUSPECTED
        verdicts.append(
            ValidationVerdict(
                finding_id=finding.finding_id,
                status=suggested,
                confidence=confidence,
                reasons=reasons,
            )
        )
    return verdicts


# ---------------------------------------------------------------------------
# VAL-005: Impact assessment engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImpactAssessment:
    finding_id: str
    base_severity: Severity
    adjusted_severity: Severity
    adjusted_cvss: float
    factors: list[str] = field(default_factory=list)


_CRITICALITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEVERITY_ORDER = list(Severity)


def assess_impact(
    finding: Finding,
    asset_criticality: str = "medium",
    internet_facing: bool = False,
) -> ImpactAssessment:
    """Adjust finding severity using simple business-context factors.

    Factors: asset criticality, internet exposure, and whether the finding is
    authentication-bypass class. The result is advisory for report prioritization.
    """
    factors: list[str] = []
    rank_delta = 0
    criticality = asset_criticality.lower()
    if criticality not in _CRITICALITY_RANK:
        raise ValueError("asset_criticality must be one of: low, medium, high, critical")
    baseline = _CRITICALITY_RANK["medium"]
    delta = _CRITICALITY_RANK[criticality] - baseline
    if delta != 0:
        rank_delta += delta
        factors.append(
            f"asset criticality '{criticality}' ({'raises' if delta > 0 else 'lowers'} priority)"
        )
    if internet_facing:
        rank_delta += 1
        factors.append("internet-facing exposure raises priority")
    if finding.type.lower() in ("auth_bypass", "default_credentials", "sql_injection"):
        rank_delta += 1
        factors.append(f"'{finding.type}' class typically escalates impact")
    base_index = _SEVERITY_ORDER.index(normalize_severity(finding.severity))
    adjusted_index = max(0, min(len(_SEVERITY_ORDER) - 1, base_index + rank_delta))
    adjusted = _SEVERITY_ORDER[adjusted_index]
    return ImpactAssessment(
        finding_id=finding.finding_id,
        base_severity=normalize_severity(finding.severity),
        adjusted_severity=adjusted,
        adjusted_cvss=cvss_for_severity(adjusted),
        factors=factors,
    )
