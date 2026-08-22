"""Vendor-grade report narrative sections (RPT-201).

Pure Markdown builders over enriched finding dicts and correlated attack-path
data. No I/O, no execution — the orchestrator composes these into ``report.md``.
Each function degrades gracefully: given no data it emits a short, honest
"nothing observed" section rather than empty or fabricated content.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..core import mitre
from .models import Severity, deduplicate_findings, normalize_severity

__all__ = [
    "executive_summary",
    "attack_coverage_section",
    "attack_path_section",
]

_SEVERITY_ORDER = list(Severity)


def _severity_rank(value: Any) -> int:
    return _SEVERITY_ORDER.index(normalize_severity(value))


def _effective_severity(finding: dict[str, Any]) -> Severity:
    """Use the impact-adjusted severity when the enrichment pass set one."""
    return normalize_severity(finding.get("adjusted_severity") or finding.get("severity"))


def executive_summary(
    findings: Iterable[dict[str, Any]], *, target: str = "the target scope"
) -> list[str]:
    """Build the executive-summary section: posture, counts, and top risks."""
    rows = list(findings)
    counts: dict[str, int] = {}
    for finding in rows:
        bucket = _effective_severity(finding).value
        counts[bucket] = counts.get(bucket, 0) + 1

    if not rows:
        return [
            "## Executive Summary",
            "",
            f"No findings were recorded for {target}. Either the scope was clean under the "
            "tests performed, or required tools/approvals were unavailable (see scan status "
            "notes). This is not a guarantee of security.",
            "",
        ]

    highest = max((_effective_severity(f) for f in rows), key=_severity_rank).value
    lines = [
        "## Executive Summary",
        "",
        f"**{len(rows)}** findings were recorded for {target}. "
        f"The highest observed severity is **{highest}**.",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in reversed(_SEVERITY_ORDER):
        if counts.get(severity.value):
            lines.append(f"| {severity.value.title()} | {counts[severity.value]} |")
    lines.append("")

    top = sorted(
        rows,
        key=lambda f: (
            -_severity_rank(_effective_severity(f)),
            -float(f.get("adjusted_cvss") or f.get("cvss_score") or 0.0),
        ),
    )[:5]
    if top:
        lines.append("**Top risks:**")
        lines.append("")
        for finding in top:
            cvss = finding.get("adjusted_cvss") or finding.get("cvss_score")
            cvss_text = f" (CVSS {cvss})" if cvss else ""
            title = finding.get("title") or finding.get("type") or "finding"
            lines.append(
                f"- **[{_effective_severity(finding).value.upper()}]** {title} — "
                f"`{finding.get('target', 'n/a')}`{cvss_text}"
            )
        lines.append("")
    return lines


def attack_coverage_section(findings: Iterable[dict[str, Any]]) -> list[str]:
    """Render an ATT&CK tactic/technique coverage table over the findings."""
    matrix = mitre.coverage_matrix(findings)
    lines = ["## MITRE ATT&CK Coverage", ""]
    if not matrix:
        lines.append("No techniques were mapped from the recorded findings.")
        lines.append("")
        return lines
    lines.extend(["| Tactic | Technique | ID | Findings |", "| --- | --- | --- | --- |"])
    for tactic, techniques in matrix.items():
        for technique in techniques:
            lines.append(
                f"| {tactic} | {technique['name']} | {technique['id']} | {technique['count']} |"
            )
    lines.append("")
    return lines


def attack_path_section(attack_paths: list[dict[str, Any]] | None) -> list[str]:
    """Render discovered attack chains as ordered, human-readable narratives."""
    lines = ["## Attack Path Analysis", ""]
    paths = attack_paths or []
    if not paths:
        lines.append(
            "No multi-stage attack chains were correlated from the current findings. "
            "Chains appear when weaknesses at different stages (e.g. exposure → injection "
            "→ privilege) co-occur on a host or across hosts."
        )
        lines.append("")
        return lines
    lines.append(
        f"{len(paths)} candidate attack path(s) were correlated (highest-scoring first). "
        "Every path remains advisory and subject to the approval workflow."
    )
    lines.append("")
    for index, path in enumerate(paths[:10], 1):
        nodes = path.get("nodes", [])
        stages = path.get("stages", [])
        chain = " → ".join(str(node) for node in nodes)
        stage_text = " → ".join(str(stage) for stage in stages) if stages else ""
        lines.append(f"**Path {index}** (score {path.get('score', 0)}): {chain}")
        if stage_text:
            lines.append(f"  - Stages: {stage_text}")
        lines.append("")
    return lines


def enriched_or_raw(
    findings: Iterable[dict[str, Any]], enriched: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    """Prefer the enrichment pass output; fall back to deduplicated raw findings."""
    if enriched:
        return enriched
    return [finding.to_dict() for finding in deduplicate_findings(findings)]
