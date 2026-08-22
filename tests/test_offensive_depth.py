"""Tests for the vendor-grade offensive depth: MITRE mapping, enrichment,
web/API/exploitation/post-exploitation agents, and report narratives."""

from __future__ import annotations

import asyncio
import json

import pytest

from networkforgeai.agents.specialized import (
    APISecurityAgent,
    NetworkExploitationAgent,
    PostExploitationAgent,
    WebApplicationAgent,
)
from networkforgeai.core import mitre
from networkforgeai.core.enrichment import enrich_findings
from networkforgeai.reporting import narrative


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, findings, success=True, stderr=""):
        self.findings = findings
        self.success = success
        self.stderr = stderr


class _FakeTool:
    """Async tool double that also accepts the ``approval_details`` kwarg."""

    def __init__(self, name, findings, *, success=True, dry_run=False, raises=None):
        self.name = name
        self.approval_gateway = None
        self.dry_run = dry_run
        self._result = _FakeResult(findings, success=success)
        self._raises = raises

    def _approval_required(self):
        return False

    async def execute_async(self, target, options=None, timeout=300, *, approval_details=None):
        if self._raises is not None:
            raise self._raises
        return self._result


async def _auto_approve(*args, **kwargs):
    return True, {"operator": "test"}


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------


def test_mitre_direct_and_stage_fallback_and_matrix():
    direct = mitre.techniques_for_type("sql_injection")
    assert direct and direct[0].technique_id == "T1190"
    assert mitre.techniques_for_type("totally_unknown_type") == []
    # Stage fallback: unknown type but recognizable stage keyword.
    annotated = mitre.annotate_finding({"type": "smb_relay", "target": "h"})
    assert annotated["attack_techniques"][0]["tactic"] == "Lateral Movement"
    # Existing mapping is preserved, not overwritten.
    pre = {"type": "xss", "attack_techniques": [{"id": "X", "name": "n", "tactic": "t"}]}
    assert mitre.annotate_finding(pre)["attack_techniques"][0]["id"] == "X"
    matrix = mitre.coverage_matrix(
        [{"type": "open_port", "target": "h"}, {"type": "open_port", "target": "h2"}]
    )
    assert matrix["Discovery"][0]["count"] == 2


# ---------------------------------------------------------------------------
# Enrichment engine
# ---------------------------------------------------------------------------


def test_enrichment_scores_correlates_and_suppresses_false_positives():
    raw = [
        {
            "type": "open_port",
            "target": "10.0.0.5",
            "title": "22 open",
            "severity": "informational",
        },
        {
            "type": "sql_injection",
            "target": "http://10.0.0.5/app",
            "title": "SQLi id",
            "severity": "critical",
            "evidence": [{"kind": "tool", "content": "sqlmap: id injectable"}],
        },
        {
            "type": "default_credentials",
            "target": "10.0.0.5",
            "title": "admin default",
            "severity": "high",
            "evidence": [{"kind": "tool", "content": "admin:admin"}],
        },
        # honeypot signature -> should be suppressed as a false positive
        {
            "type": "xss",
            "target": "honeypot.internal",
            "title": "reflected",
            "severity": "medium",
            "evidence": [{"kind": "t", "content": "honeypot marker"}],
        },
    ]
    result = enrich_findings(raw, targets=["10.0.0.5"], internet_facing=True)
    assert result.suppressed_false_positives == 1
    assert result.highest_severity == "critical"
    sqli = next(f for f in result.findings if f["type"] == "sql_injection")
    assert sqli["cvss_score"] == 9.8
    assert sqli["attack_techniques"][0]["id"] == "T1190"
    assert sqli["metadata"]["owasp_top10"].startswith("A03")
    assert sqli["poc"]["requires_human_approval"] is True
    # internet-facing + credential class escalates default creds severity.
    creds = next(f for f in result.findings if f["type"] == "default_credentials")
    assert creds["adjusted_severity"] == "critical"
    assert "Initial Access" in result.attack_coverage


def test_enrichment_empty_input_is_well_formed():
    result = enrich_findings([])
    assert result.findings == []
    assert result.attack_paths["paths"] == []
    assert result.highest_severity == "informational"


# ---------------------------------------------------------------------------
# Web application agent
# ---------------------------------------------------------------------------


def test_web_agent_runs_gated_scanner_and_emits_findings():
    async def scenario():
        agent = WebApplicationAgent(
            tool_registry={
                "nikto": _FakeTool(
                    "nikto",
                    [
                        {
                            "type": "web_vulnerability",
                            "url": "http://site/",
                            "description": "Server leaks version",
                            "severity": "medium",
                        }
                    ],
                )
            }
        )
        agent.request_approval = _auto_approve  # type: ignore[method-assign]
        res = await agent.execute("web", {"target": "site", "discovered_urls": ["http://site/"]})
        assert res["context_updates"]["web_testing_status"] == "completed"
        assert res["findings"][0]["type"] == "web_vulnerability"
        assert res["findings"][0]["source"] == "tool:nikto"

    run(scenario())


def test_web_agent_rejection_yields_no_findings():
    async def scenario():
        agent = WebApplicationAgent(tool_registry={"nikto": _FakeTool("nikto", [])})

        async def deny(*a, **k):
            return False, None

        agent.request_approval = deny  # type: ignore[method-assign]
        res = await agent.execute("web", {"discovered_urls": ["http://site/"]})
        assert res["findings"] == []
        assert res["context_updates"]["web_tool_status"]["nikto"] == "rejected"

    run(scenario())


def test_web_agent_no_target_and_no_tool_paths():
    async def scenario():
        no_target = await WebApplicationAgent().execute("web", {})
        assert no_target["context_updates"]["web_testing_status"] == "no_target"
        no_tool = await WebApplicationAgent().execute("web", {"target": "site"})
        assert no_tool["context_updates"]["web_testing_status"] == "no_tool_or_model"

    run(scenario())


# ---------------------------------------------------------------------------
# API security agent
# ---------------------------------------------------------------------------


def test_api_agent_probes_graphql_and_jwt():
    async def scenario():
        agent = APISecurityAgent(
            tool_registry={
                "graphql-probe": _FakeTool(
                    "graphql-probe",
                    [
                        {
                            "type": "introspection_enabled",
                            "summary": "introspection on",
                            "severity": "medium",
                        }
                    ],
                ),
                "jwt-analyzer": _FakeTool(
                    "jwt-analyzer",
                    [{"type": "jwt_alg_none", "summary": "alg=none accepted", "severity": "high"}],
                ),
            }
        )
        agent.request_approval = _auto_approve  # type: ignore[method-assign]
        res = await agent.execute(
            "api",
            {
                "target": "api.site",
                "graphql_endpoint": "https://api.site/graphql",
                "jwt_token": "a.b.c",
            },
        )
        assert res["context_updates"]["api_testing_status"] == "completed"
        types = {f["type"] for f in res["findings"]}
        assert {"introspection_enabled", "jwt_alg_none"} <= types

    run(scenario())


def test_api_agent_no_surface():
    async def scenario():
        res = await APISecurityAgent().execute("api", {"target": "x"})
        assert res["context_updates"]["api_testing_status"] == "no_api_surface"

    run(scenario())


# ---------------------------------------------------------------------------
# Network exploitation agent (full exploit, always approval-gated)
# ---------------------------------------------------------------------------


def test_exploit_agent_requires_tool_and_explicit_module():
    async def scenario():
        no_tool = await NetworkExploitationAgent().execute("exploit", {"target": "h"})
        assert no_tool["context_updates"]["exploitation_status"] == "no_exploit_tool_registered"

        no_module = await NetworkExploitationAgent(
            tool_registry={"metasploit": _FakeTool("metasploit", [])}
        ).execute("exploit", {"target": "h"})
        assert no_module["context_updates"]["exploitation_status"] == "no_exploit_module_specified"

    run(scenario())


def test_exploit_agent_emits_validated_finding_on_session():
    async def scenario():
        agent = NetworkExploitationAgent(
            tool_registry={
                "metasploit": _FakeTool(
                    "metasploit",
                    [{"type": "session_opened", "session_id": 1, "summary": "session 1 opened"}],
                )
            }
        )
        context = {
            "target": "10.0.0.9",
            "exploit_plan": [
                {
                    "target": "10.0.0.9",
                    "module": "exploit/linux/smb/example",
                    "justification": "authorized engagement ticket #42",
                }
            ],
        }
        res = await agent.execute("exploit", context)
        assert res["context_updates"]["exploitation_status"] == "completed"
        finding = res["findings"][0]
        assert finding["type"] == "remote_code_execution"
        assert finding["severity"] == "critical"
        assert finding["validated"] is True
        assert finding["metadata"]["module"] == "exploit/linux/smb/example"

    run(scenario())


def test_exploit_agent_records_rejection_without_fabrication():
    async def scenario():
        agent = NetworkExploitationAgent(
            tool_registry={
                "metasploit": _FakeTool("metasploit", [], raises=PermissionError("denied"))
            }
        )
        res = await agent.execute(
            "exploit",
            {"target": "h", "exploit_plan": [{"target": "h", "module": "exploit/x"}]},
        )
        assert res["findings"] == []
        assert res["context_updates"]["exploitation_attempts"][0]["status"] == "rejected"

    run(scenario())


# ---------------------------------------------------------------------------
# Post-exploitation planning
# ---------------------------------------------------------------------------


def test_post_exploitation_plan_grounded_and_template():
    async def scenario():
        grounded = await PostExploitationAgent().execute(
            "post",
            {"target": "h", "findings": [{"type": "session_opened", "target": "h"}]},
        )
        assert grounded["context_updates"]["post_exploitation_grounded"] is True
        plan = grounded["context_updates"]["post_exploitation_plan"]
        assert plan and all(step["requires_approval"] for step in plan)
        assert all(step["attack_techniques"] for step in plan)

        template = await PostExploitationAgent().execute("post", {"target": "h"})
        assert template["context_updates"]["post_exploitation_grounded"] is False
        assert template["context_updates"]["post_exploitation_blocked"] is True

    run(scenario())


# ---------------------------------------------------------------------------
# Report narrative
# ---------------------------------------------------------------------------


def test_narrative_sections_render():
    findings = [
        {
            "type": "sql_injection",
            "target": "http://site/app",
            "title": "SQLi",
            "severity": "critical",
            "adjusted_severity": "critical",
            "adjusted_cvss": 9.8,
        },
        {"type": "open_port", "target": "site", "title": "22 open", "severity": "informational"},
    ]
    summary = "\n".join(narrative.executive_summary(findings, target="site"))
    assert "Executive Summary" in summary and "Top risks" in summary and "CVSS 9.8" in summary
    coverage = "\n".join(narrative.attack_coverage_section(findings))
    assert "MITRE ATT&CK Coverage" in coverage and "T1190" in coverage
    paths = "\n".join(
        narrative.attack_path_section(
            [{"nodes": ["a::recon", "a::injection"], "score": 6, "stages": ["recon", "injection"]}]
        )
    )
    assert "Attack Path Analysis" in paths and "→" in paths


def test_narrative_empty_states():
    assert "No findings" in "\n".join(narrative.executive_summary([]))
    assert "No techniques" in "\n".join(narrative.attack_coverage_section([]))
    assert "No multi-stage" in "\n".join(narrative.attack_path_section([]))


# ---------------------------------------------------------------------------
# CLI exploit-plan loader
# ---------------------------------------------------------------------------


def test_cli_load_exploit_plan(tmp_path):
    from networkforgeai.cli import _load_exploit_plan

    assert _load_exploit_plan(None) is None
    good = tmp_path / "plan.json"
    good.write_text(json.dumps([{"target": "h", "module": "exploit/x"}]))
    assert _load_exploit_plan(str(good))[0]["module"] == "exploit/x"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([{"target": "h"}]))  # missing module
    with pytest.raises(SystemExit):
        _load_exploit_plan(str(bad))
