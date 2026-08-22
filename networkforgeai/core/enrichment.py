"""Finding enrichment and correlation pipeline (ADV-202).

Turns raw agent/tool finding dicts into vendor-grade, decision-ready records by
composing the engines that already exist in the codebase:

* :mod:`reporting.models`      -- canonical normalization + deduplication
* :mod:`reporting.compliance`  -- OWASP/PTES/NIST/ISO/PCI mapping
* :mod:`core.validation`       -- CVSS v3.1 scoring, false-positive elimination,
                                  business-impact assessment, advisory PoC steps
* :mod:`core.mitre`            -- ATT&CK technique tagging
* :mod:`core.attack_paths`     -- chained attack-path discovery

Everything here is advisory computation over data captured elsewhere. It never
executes an offensive action and never invents a finding: an empty input yields
an empty, well-formed report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..reporting.compliance import annotate_compliance
from ..reporting.models import (
    Finding,
    FindingStatus,
    Severity,
    deduplicate_findings,
    normalize_severity,
    prepare_findings,
)
from . import mitre
from .attack_paths import discover_attack_paths
from .validation import (
    assess_impact,
    cvss_for_severity,
    eliminate_false_positives,
    generate_poc,
)

__all__ = ["EnrichmentResult", "enrich_findings"]


@dataclass
class EnrichmentResult:
    """Correlated, scored output of the enrichment pipeline."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: dict[str, Any] = field(default_factory=dict)
    attack_coverage: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    severity_counts: dict[str, int] = field(default_factory=dict)
    highest_severity: str = "informational"
    suppressed_false_positives: int = 0

    def to_context_updates(self) -> dict[str, Any]:
        """Shape the result for the orchestrator shared context."""
        return {
            "enriched_findings": self.findings,
            "attack_paths": self.attack_paths.get("paths", []),
            "attack_path_graph": self.attack_paths.get("graph", {}),
            "attack_coverage": self.attack_coverage,
            "severity_counts": self.severity_counts,
            "highest_severity": self.highest_severity,
            "suppressed_false_positives": self.suppressed_false_positives,
        }


def _cvss_for(finding: Finding) -> float:
    """Prefer an explicit CVSS score, else derive one from severity."""
    if finding.cvss_score is not None:
        return float(finding.cvss_score)
    return cvss_for_severity(finding.severity)


def enrich_findings(
    raw_findings: Iterable[dict[str, Any]],
    *,
    targets: list[str] | None = None,
    asset_criticality: str = "medium",
    internet_facing: bool = False,
    drop_false_positives: bool = True,
) -> EnrichmentResult:
    """Correlate, score, and annotate raw findings into a decision-ready set.

    Steps:
      1. Normalize + deduplicate into canonical :class:`Finding` records.
      2. Eliminate obvious false positives (advisory verdicts).
      3. Score each finding: CVSS, business-impact-adjusted severity, ATT&CK
         techniques, compliance mappings, and advisory PoC steps.
      4. Discover chained attack paths across the surviving findings.
      5. Summarize ATT&CK tactic coverage and severity distribution.
    """
    findings = deduplicate_findings(raw_findings)

    verdicts = {v.finding_id: v for v in eliminate_false_positives(findings)}

    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        verdict = verdicts.get(finding.finding_id)
        if verdict and verdict.status is FindingStatus.FALSE_POSITIVE and drop_false_positives:
            suppressed += 1
            continue
        kept.append(finding)

    enriched: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}
    for finding in kept:
        verdict = verdicts.get(finding.finding_id)
        impact = assess_impact(
            finding, asset_criticality=asset_criticality, internet_facing=internet_facing
        )
        poc = generate_poc(finding)

        record = finding.to_dict()
        record["cvss_score"] = _cvss_for(finding)
        record["adjusted_severity"] = impact.adjusted_severity.value
        record["adjusted_cvss"] = impact.adjusted_cvss
        record["impact_factors"] = impact.factors
        if verdict is not None:
            record["validation"] = {
                "status": verdict.status.value,
                "confidence": verdict.confidence,
                "reasons": verdict.reasons,
            }
        record["poc"] = {
            "commands": poc.commands,
            "requires_human_approval": poc.requires_human_approval,
            "notes": poc.notes,
        }
        record = mitre.annotate_finding(record)
        enriched.append(record)

        bucket = impact.adjusted_severity.value
        severity_counts[bucket] = severity_counts.get(bucket, 0) + 1

    # Compliance mapping mutates metadata in place on the enriched dicts.
    annotate_compliance(enriched)

    attack_paths = discover_attack_paths(enriched, targets=targets)
    coverage = mitre.coverage_matrix(enriched)

    order = list(Severity)
    highest = Severity.INFORMATIONAL
    for row in enriched:
        candidate = normalize_severity(row.get("adjusted_severity"))
        if order.index(candidate) > order.index(highest):
            highest = candidate

    return EnrichmentResult(
        findings=enriched,
        attack_paths=attack_paths,
        attack_coverage=coverage,
        severity_counts=severity_counts,
        highest_severity=highest.value,
        suppressed_false_positives=suppressed,
    )


def enriched_dicts(raw_findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convenience: return only the enriched finding dicts (deduplicated)."""
    return enrich_findings(prepare_findings(raw_findings)).findings
