"""Tests for remediation re-test planning (ADV-105)."""

from networkforgeai.core.revalidation import (
    RetestAction,
    build_retest_plan,
    suggest_tool_for_finding,
)

_FINDINGS = [
    {
        "type": "sqli",
        "target": "example.com",
        "severity": "high",
        "status": "remediated",
    },
    {
        "type": "open-tls-port",
        "target": "example.com",
        "severity": "medium",
        "status": "remediated",
    },
    {
        "type": "xss",
        "target": "example.com",
        "severity": "high",
        "status": "suspected",  # not remediated: excluded
    },
]


def test_plan_only_includes_remediated_findings():
    plan = build_retest_plan(_FINDINGS)
    assert [action.finding_type for action in plan] == ["sqli", "open-tls-port"]


def test_plan_maps_finding_types_to_inventory_tools():
    plan = build_retest_plan(_FINDINGS)
    by_type = {action.finding_type: action for action in plan}
    assert by_type["sqli"].tool_name == "sqlmap"
    assert by_type["open-tls-port"].tool_name == "nikto"


def test_every_action_requires_approval():
    for action in build_retest_plan(_FINDINGS):
        assert isinstance(action, RetestAction)
        assert action.requires_approval is True


def test_status_filter_can_be_widened():
    plan = build_retest_plan(_FINDINGS, statuses={"remediated", "suspected"})
    assert len(plan) == 3


def test_suggest_tool_defaults_and_matches():
    assert suggest_tool_for_finding("jwt_alg_none") == "jwt-analyzer"
    assert suggest_tool_for_finding("graphql_introspection") == "graphql-probe"
    assert suggest_tool_for_finding("totally-unknown") == "nikto"


def test_empty_input_yields_empty_plan():
    assert build_retest_plan([]) == []
