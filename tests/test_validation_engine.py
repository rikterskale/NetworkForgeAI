import pytest

from networkforgeai.core.validation import (
    assess_impact,
    cvss_base_score,
    cvss_for_severity,
    eliminate_false_positives,
    generate_poc,
)
from networkforgeai.reporting import Evidence, Finding


def _finding(**overrides):
    defaults = {
        "type": "sql_injection",
        "target": "example.com/login",
        "title": "SQLi",
        "severity": "high",
    }
    defaults.update(overrides)
    return Finding(**defaults)


def test_cvss_known_vectors():
    assert cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss_base_score("AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N") == 5.9
    assert cvss_base_score("AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N") == 0.0
    with pytest.raises(ValueError):
        cvss_base_score("AV:N/AC:L")


def test_cvss_severity_baseline_mapping():
    assert cvss_for_severity("info") == 0.0
    assert cvss_for_severity("critical") == 9.8
    assert 0 < cvss_for_severity("medium") < 10


def test_generate_poc_is_advisory_and_formatted():
    finding = _finding(metadata={"port": 8080})
    poc = generate_poc(finding)
    assert poc.requires_human_approval is True
    assert any("example.com" in command for command in poc.commands)
    unknown = generate_poc(_finding(type="novel_finding"))
    assert unknown.commands and "no template" in unknown.commands[0]


def test_false_positive_eliminator_signals():
    corroborated = _finding(
        evidence=[
            Evidence("log", "stack trace", "scanner"),
            Evidence("screenshot", "proof", "manual"),
        ]
    )
    suspected = _finding(title="Suspect")
    honeypot = _finding(target="honeypot.local", evidence=[Evidence("log", "noise", "scan")])
    verdicts = {
        verdict.finding_id: verdict
        for verdict in eliminate_false_positives([corroborated, suspected, honeypot])
    }
    assert verdicts[corroborated.finding_id].status.value == "validated"
    assert verdicts[suspected.finding_id].status.value == "suspected"
    fp = verdicts[honeypot.finding_id]
    assert fp.status.value == "false_positive"
    assert not fp.corroborated
    assert any("honeypot" in reason for reason in fp.reasons)


def test_impact_assessment_adjusts_severity():
    base = _finding(severity="medium")
    raised = assess_impact(base, asset_criticality="critical", internet_facing=True)
    assert raised.adjusted_severity.value in ("high", "critical")
    assert raised.adjusted_cvss >= 6.5
    assert raised.factors
    lowered = assess_impact(base, asset_criticality="low")
    # low asset criticality (-1) cancels the sql_injection escalation (+1)
    assert lowered.adjusted_severity.value == "medium"
    assert any("lowers" in factor for factor in lowered.factors)
    with pytest.raises(ValueError):
        assess_impact(base, asset_criticality="cosmic")
