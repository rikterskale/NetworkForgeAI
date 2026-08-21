"""Cloud and directory-environment audit tools (TLS-201..205).

Wrappers around well-known, read-mostly cloud security auditing binaries:
ScoutSuite (AWS/GCP), ROADtools (Azure), kube-hunter (Kubernetes), and
BloodHound's Python collector (Active Directory). All of these touch cloud
or domain infrastructure with provided credentials, so every tool in this
module requires explicit human approval before execution.
"""

import json
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel


class _CloudAuditTool(BaseTool):
    """Shared behavior for credential-based cloud audits (approval required)."""

    category = ToolCategory.CLOUD
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options: Dict[str, Any] = {}

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if isinstance(payload, dict) and payload.get("finding"):
                item = dict(payload)
                item.setdefault("confidence", "medium")
                findings.append(item)
        if not findings:
            findings.append(
                {
                    "type": f"{self.name}_completed",
                    "summary": "Audit completed; review the generated provider report",
                    "severity": "informational",
                    "confidence": "low",
                }
            )
        return findings


class AwsAuditTool(_CloudAuditTool):
    """ScoutSuite-based AWS posture audit (TLS-201)."""

    name = "cloud-aws"
    description = "Audit AWS account posture with ScoutSuite (read-only checks)"

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        command = ["scoutsuite", "--provider", "aws", "--report-name", f"nfa-{target}"]
        profile = opts.get("profile")
        if profile:
            command += ["--profile", str(profile)]
        regions = opts.get("regions")
        if regions:
            command += ["--regions", str(regions)]
        if opts.get("no-browser", True):
            command += ["--no-browser"]
        return command


class AzureAuditTool(_CloudAuditTool):
    """ROADtools-based Entra ID collection (TLS-202)."""

    name = "cloud-azure"
    description = "Collect Azure/Entra ID tenant data with roadrecon for offline analysis"

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        tenant = str(opts.get("tenant") or target)
        command = ["roadrecon", "gather", "-d", tenant]
        username = opts.get("username")
        if username:
            command += ["-u", str(username)]
        if opts.get("use-device-code"):
            command += ["--device-code"]
        return command


class GcpAuditTool(_CloudAuditTool):
    """ScoutSuite-based GCP posture audit (TLS-203)."""

    name = "cloud-gcp"
    description = "Audit GCP project posture with ScoutSuite (read-only checks)"

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        command = [
            "scoutsuite",
            "--provider",
            "gcp",
            "--report-name",
            f"nfa-{target}",
            "--no-browser",
        ]
        project_ids = opts.get("project_ids")
        if project_ids:
            command += ["--project-ids", str(project_ids)]
        service_account = opts.get("service_account")
        if service_account:
            command += ["--service-account", str(service_account)]
        folder_id = opts.get("folder_id")
        if folder_id:
            command += ["--folder-id", str(folder_id)]
        organization_id = opts.get("organization_id")
        if organization_id:
            command += ["--organization-id", str(organization_id)]
        return command


class KubernetesHuntTool(_CloudAuditTool):
    """kube-hunter based cluster probing (TLS-204)."""

    name = "kube-hunter"
    description = "Probe Kubernetes clusters for known weaknesses with kube-hunter"
    risk_level = ToolRiskLevel.HIGH

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        mode = str(opts.get("mode") or "remote")
        command = ["kube-hunter", f"--{mode}", target, "--report", "json"]
        if opts.get("cis"):
            command += ["--cis"]
        return command

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        try:
            payload = json.loads(stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return super().parse_findings(stdout, stderr)
        findings: List[Dict[str, Any]] = []
        for vuln in payload if isinstance(payload, list) else payload.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            findings.append(
                {
                    "type": "k8s_weakness",
                    "summary": vuln.get("description", "cluster weakness reported"),
                    "id": vuln.get("id"),
                    "severity": str(vuln.get("severity", "unknown")).lower(),
                    "confidence": "high",
                }
            )
        return findings


class AdReconTool(_CloudAuditTool):
    """BloodHound Python collector for Active Directory reconnaissance (TLS-205)."""

    name = "ad-recon"
    description = "Collect Active Directory attack-path data with bloodhound-python"
    risk_level = ToolRiskLevel.HIGH

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        if "." not in target or " " in target:
            raise ValueError("ad-recon requires a dotted Active Directory domain name")
        opts = {**self.default_options, **(options or {})}
        command = ["bloodhound-python", "-d", target, "-c", "All"]
        username = opts.get("username")
        if username:
            command += ["-u", str(username)]
        password = opts.get("password")
        if password:
            command += ["-p", str(password)]
        nameserver = opts.get("nameserver")
        if nameserver:
            command += ["-ns", str(nameserver)]
        return command

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        collected = sum(1 for line in stdout.splitlines() if "INFO" in line and ".json" in line)
        findings.append(
            {
                "type": "ad_recon_completed",
                "summary": (
                    f"BloodHound collection finished ({collected} data artifacts logged); "
                    "ingest archives into BloodHound for path analysis"
                ),
                "severity": "informational",
                "confidence": "high",
            }
        )
        return findings
