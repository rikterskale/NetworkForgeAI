"""Tests for cloud and directory audit tools (TLS-201..205)."""

import pytest

from networkforgeai.core.scope import ScopePolicy
from networkforgeai.tools import (
    AdReconTool,
    AwsAuditTool,
    AzureAuditTool,
    GcpAuditTool,
    KubernetesHuntTool,
    get_available_tools,
)


@pytest.fixture
def policy():
    return ScopePolicy(["example.com", "10.0.0.0/8"])


def test_cloud_tools_registered_and_risk_gated():
    tools = get_available_tools()
    for name in ("cloud-aws", "cloud-azure", "cloud-gcp", "kube-hunter", "ad-recon"):
        assert name in tools


def test_aws_audit_build_command(policy):
    tool = AwsAuditTool(dry_run=True)
    tool.scope_policy = policy
    command = tool.build_command("example.com", {"profile": "pentest", "regions": "us-east-1"})
    assert command[:4] == ["scoutsuite", "--provider", "aws", "--report-name"]
    assert "--profile" in command and "pentest" in command
    assert "--no-browser" in command
    result = tool.execute("example.com", {"profile": "pentest"})
    assert result.success and "[DRY RUN]" in result.stdout


def test_azure_audit_build_command(policy):
    tool = AzureAuditTool(dry_run=True)
    tool.scope_policy = policy
    command = tool.build_command(
        "example.com", {"tenant": "contoso.onmicrosoft.com", "username": "ops@contoso.com"}
    )
    assert command[0] == "roadrecon" and "-d" in command
    assert "contoso.onmicrosoft.com" in command
    result = tool.execute("example.com")
    assert result.success


def test_gcp_audit_build_command(policy):
    tool = GcpAuditTool(dry_run=True)
    tool.scope_policy = policy
    command = tool.build_command("example.com", {"project_ids": "proj-1,proj-2"})
    assert command[0] == "scoutsuite" and "gcp" in command
    assert "--project-ids" in command and "proj-1,proj-2" in command
    result = tool.execute("example.com")
    assert result.success


def test_kube_hunter_build_and_parse(policy):
    tool = KubernetesHuntTool(dry_run=True)
    tool.scope_policy = policy
    command = tool.build_command("10.0.0.5", {"mode": "remote", "cis": True})
    assert command == ["kube-hunter", "--remote", "10.0.0.5", "--report", "json", "--cis"]
    findings = tool.parse_findings(
        '[{"id": "KHV050", "severity": "medium", "description": "exposed dashboard"}]', ""
    )
    assert findings[0]["type"] == "k8s_weakness"
    assert findings[0]["id"] == "KHV050"


def test_high_risk_cloud_tools_fail_closed_without_gateway(policy):
    hunter = KubernetesHuntTool()
    hunter.scope_policy = policy
    with pytest.raises(PermissionError):
        hunter.execute("10.0.0.5")
    recon = AdReconTool()
    recon.scope_policy = policy
    with pytest.raises(PermissionError):
        recon.execute("example.com")


def test_ad_recon_requires_dotted_domain(policy):
    tool = AdReconTool(dry_run=True)
    tool.scope_policy = policy
    with pytest.raises(ValueError):
        tool.build_command("not-a-domain")
    command = tool.build_command("corp.example.com", {"username": "svc"})
    assert command[0] == "bloodhound-python" and "-d" in command
    assert "corp.example.com" in command


def test_ad_recon_parse_findings_summarizes_collection():
    tool = AdReconTool()
    stdout = "INFO: wrote computers.json\nINFO: wrote groups.json\nother"
    findings = tool.parse_findings(stdout, "")
    assert findings[0]["type"] == "ad_recon_completed"
    assert "2 data artifacts" in findings[0]["summary"]


def test_generic_parse_findings_json_lines():
    tool = AwsAuditTool()
    findings = tool.parse_findings('{"finding": true, "type": "s3_public"}\nnoise', "")
    assert findings[0]["type"] == "s3_public"
    fallback = tool.parse_findings("", "")
    assert fallback[0]["confidence"] == "low"


def test_cloud_tools_require_scope_even_in_dry_run():
    tool = AwsAuditTool(dry_run=True)
    with pytest.raises(ValueError):
        tool.execute("unscoped-target")
