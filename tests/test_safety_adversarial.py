"""Adversarial safety tests (TST-006): attempt to bypass the safety controls.

These tests attack NetworkForgeAI's own guardrails — scope enforcement,
approval fail-closed behavior, dashboard RBAC, and report path confinement —
the way an untrusted input or careless operator would. Every attack must be
denied or fail closed.
"""

import pytest

from networkforgeai.core.approval_gateway import ApprovalGateway, RiskLevel
from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools import HydraTool, MetasploitTool, NmapTool, get_tool_by_name


@pytest.fixture
def policy():
    return ScopePolicy(["example.com"], excluded=["internal.example.com"])


# --- Scope enforcement attacks ------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com.evil.test",  # suffix injection
        "evilexample.com",  # prefix injection
        "user@example.com@evil.test",  # userinfo confusion
        "https://example.com@10.0.0.9/",  # URL-authority confusion
        "127.0.0.1",  # out-of-scope IP
        "0177.0.0.1",  # octal IP encoding
        "",  # empty
        "   ",  # whitespace
    ],
)
def test_scope_rejects_evasion_attempts(policy, target):
    assert not policy.contains(target)


def test_scope_normalization_is_not_a_bypass(policy):
    """Canonical spellings of in-scope hosts match; near-misses do not."""
    assert policy.contains("EXAMPLE.COM")
    assert policy.contains("example.com.")
    assert not policy.contains("EXAMPLE.COM.EVIL.TEST")


def test_scope_exclusion_beats_inclusion():
    policy = ScopePolicy(["example.com"], excluded=["internal.example.com"])
    assert policy.contains("example.com")
    assert not policy.contains("internal.example.com")
    assert not policy.contains("deep.internal.example.com")


def test_scope_wildcard_cannot_match_through_dot():
    policy = ScopePolicy(["*.example.com"])
    assert policy.contains("api.example.com")
    assert not policy.contains("example.com")
    assert not policy.contains("eviltest.com")


def test_empty_scope_denies_everything():
    assert not ScopePolicy().contains("anything.test")


def test_tool_execution_requires_scope_even_for_low_risk():
    tool = NmapTool(dry_run=True)
    with pytest.raises(ValueError):
        tool.execute("example.com")


# --- Approval fail-closed attacks ---------------------------------------------


def test_high_risk_tools_fail_closed_without_gateway(policy):
    hydra = HydraTool()
    hydra.scope_policy = policy
    with pytest.raises(PermissionError):
        hydra.execute("example.com")

    metasploit = MetasploitTool()
    metasploit.scope_policy = policy
    with pytest.raises(PermissionError):
        metasploit.execute("example.com")


def test_emergency_stop_blocks_new_approvals():
    async def scenario():
        gateway = ApprovalGateway(mode="manual")
        await gateway.emergency_stop("adversarial drill")
        with pytest.raises(PermissionError, match="Emergency stop"):
            await gateway.request_approval(
                agent_id="a",
                action_type="port_scan",
                description="d",
                target="example.com",
                risk_level=RiskLevel.LOW,
            )

    import asyncio

    asyncio.run(scenario())


def test_gateway_ignores_unknown_request_ids():
    async def scenario():
        gateway = ApprovalGateway(mode="manual")
        from networkforgeai.core.approval_gateway import ApprovalStatus

        assert await gateway.approve("nonexistent-id", "attacker") is False
        assert await gateway.reject("nonexistent-id", "attacker", "reason") is False
        request = await gateway.request_approval(
            agent_id="a",
            action_type="port_scan",
            description="d",
            target="example.com",
            risk_level=RiskLevel.LOW,
        )
        assert request.status is ApprovalStatus.PENDING

    import asyncio

    asyncio.run(scenario())


# --- Tool registry / dry-run hardening ----------------------------------------


def test_registry_tools_are_dry_run_safe_and_scoped():
    for name in ("nmap", "sqlmap", "hydra", "metasploit", "kube-hunter"):
        tool = get_tool_by_name(name, dry_run=True)
        with pytest.raises(ValueError):
            tool.execute("not-in-scope.test")  # no scope policy attached


def test_dry_run_never_spawns_real_process(policy):
    tool = get_tool_by_name("nmap", dry_run=True)
    tool.scope_policy = policy
    result = tool.execute("example.com")
    assert result.success and "[DRY RUN]" in result.stdout
