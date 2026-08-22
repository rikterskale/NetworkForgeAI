"""
Reconnaissance Agent - Passive and active information gathering

Capabilities:
- Host liveness / DNS resolution (passive, stdlib)
- Port scanning via the registered ``nmap``/``masscan`` tool wrappers
- Service fingerprinting from real scan output
- LLM-assisted triage of collected evidence (advisory only)

This agent never fabricates results. When a required tool wrapper is not
registered (or its binary is unavailable), it records an explicit
``*_status`` note in ``context_updates`` and returns no findings rather than
inventing data. Active scanning requires human approval through the gateway.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List

from ..core.approval_gateway import RiskLevel
from ..core.base_agent import AgentStatus, BaseAgent


class ReconAgent(BaseAgent):
    """Reconnaissance agent that drives real tool wrappers, not simulations."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="ReconAgent", **kwargs)
        self.discovered_hosts: List[str] = []
        self.discovered_ports: List[Dict[str, Any]] = []
        self.technologies: List[Dict[str, Any]] = []

    def get_capabilities(self) -> List[str]:
        return [
            "reconnaissance",
            "subdomain_enumeration",
            "port_scanning",
            "service_fingerprinting",
            "technology_detection",
            "osint_collection",
        ]

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reconnaissance tasks against an authorized target."""
        self.current_task = task
        self.status = AgentStatus.RUNNING

        results: Dict[str, Any] = {"task": task, "findings": [], "context_updates": {}}

        try:
            if task == "enumerate_subdomains":
                await self._resolve_host(context, results)
            elif task == "scan_ports":
                await self._scan_ports(context, results)
            elif task == "fingerprint_services":
                await self._fingerprint_services(context, results)
            elif task == "detect_technologies":
                await self._detect_technologies(context, results)
            else:
                # General recon: passive host resolution plus a port scan when a
                # scanner tool is available. Never fabricate when it is not.
                await self._resolve_host(context, results)
                await self._scan_ports(context, results)

        except Exception as e:  # noqa: BLE001 - reported as task error, never fatal
            results["error"] = str(e)
            self.status = AgentStatus.ERROR

        finally:
            self.status = AgentStatus.IDLE
            from datetime import datetime, timezone

            self.last_active = datetime.now(timezone.utc)

        return results

    async def _resolve_host(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Passively confirm a host resolves via DNS (stdlib, no fabrication)."""
        target = context.get("target", "")
        if not target:
            results["context_updates"]["recon_status"] = "no_target"
            return

        try:
            addresses = sorted({str(info[4][0]) for info in socket.getaddrinfo(target, None)})
        except (socket.gaierror, OSError):
            results["context_updates"]["recon_status"] = "unresolved"
            return

        for address in addresses:
            finding = {
                "type": "host_resolution",
                "title": f"Host resolves: {target} -> {address}",
                "severity": "Informational",
                "target": target,
                "confidence": "high",
                "source": "dns:getaddrinfo",
                "description": f"{target} resolves to {address} via DNS.",
                "poc": f"nslookup {target}",
                "reproduction_steps": f"1. Run: nslookup {target}\n2. Confirm it resolves to {address}",
                "remediation": "Ensure all published DNS records are intended and documented.",
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            if address not in self.discovered_hosts:
                self.discovered_hosts.append(address)

        results["context_updates"]["discovered_hosts"] = self.discovered_hosts

    async def _scan_ports(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Run an approved, real port scan via a registered scanner tool wrapper."""
        target = context.get("target", "")
        if not target:
            results["context_updates"]["port_scan_status"] = "no_target"
            return

        tool_name = (
            "nmap" if self.has_tool("nmap") else ("masscan" if self.has_tool("masscan") else "")
        )
        if not tool_name:
            results["context_updates"]["port_scan_status"] = "no_scanner_tool_registered"
            return

        # A dry-run only previews the command; nothing executes, so no approval
        # is warranted. Live scans still require explicit human approval.
        is_dry_run = getattr(self.tool_registry.get(tool_name), "dry_run", False)
        if not is_dry_run:
            approved, _ = await self.request_approval(
                action_type="port_scan",
                description=f"Perform a TCP port scan on {target} to identify open services",
                target=target,
                risk_level=RiskLevel.MEDIUM,
                details={"tool": tool_name},
                timeout_seconds=600,
            )
            if not approved:
                results["context_updates"]["port_scan_status"] = "rejected"
                return

        tool_result = await self.run_tool(tool_name, target)
        if tool_result is None:
            results["context_updates"]["port_scan_status"] = "tool_unavailable"
            return
        if not tool_result.success:
            results["context_updates"]["port_scan_status"] = "scan_failed"
            results["context_updates"]["port_scan_error"] = tool_result.stderr[:500]
            return

        for parsed in tool_result.findings:
            if parsed.get("type") != "open_port":
                continue
            port = parsed.get("port")
            protocol = parsed.get("protocol", "tcp")
            service = parsed.get("service", "unknown")
            version = parsed.get("version")
            finding = {
                "type": "open_port",
                "title": f"Open Port: {port}/{protocol} ({service})",
                "severity": "Informational",
                "target": target,
                "port": port,
                "protocol": protocol,
                "service": service,
                "confidence": parsed.get("confidence", "high"),
                "source": f"tool:{tool_name}",
                "description": f"Port {port}/{protocol} is open running {service}.",
                "poc": f"nc -zv {target} {port}",
                "reproduction_steps": f"1. Run: nc -zv {target} {port}\n2. Observe the successful connection",
                "remediation": "Confirm the service is required and restrict/patch it as appropriate.",
                "raw": parsed,
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            self.discovered_ports.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "host": target,
                }
            )

        results["context_updates"]["discovered_ports"] = self.discovered_ports
        results["context_updates"]["port_scan_status"] = "completed"

    async def _fingerprint_services(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Fingerprint services from real port data; no fabrication when absent."""
        ports = context.get("discovered_ports") or self.discovered_ports
        if not ports:
            results["context_updates"]["fingerprint_status"] = "no_ports_discovered"
            return

        # Version data comes from the scanner's own -sV output captured during the
        # port scan. Surface only what was actually observed.
        emitted = 0
        for port_info in ports:
            version = port_info.get("version")
            if not version:
                continue
            finding = {
                "type": "service_version",
                "title": f"Service version: {port_info.get('service', 'unknown')} {version}",
                "severity": "Informational",
                "target": port_info.get("host", context.get("target", "")),
                "confidence": "medium",
                "source": "tool:nmap",
                "description": f"Version {version} observed on port {port_info.get('port')}.",
                "poc": f"nmap -sV -p {port_info.get('port')} {port_info.get('host', '')}",
                "reproduction_steps": "1. Re-run nmap -sV against the port\n2. Compare the reported banner",
                "remediation": "Keep services patched to a supported version.",
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            emitted += 1

        results["context_updates"]["fingerprint_status"] = (
            "completed" if emitted else "no_version_data"
        )

    async def _detect_technologies(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Detect web technologies via a registered tool; no fabrication otherwise."""
        target = context.get("target", "")
        if not self.has_tool("browser") and not self.has_tool("whatweb"):
            results["context_updates"]["technology_status"] = "no_fingerprint_tool_registered"
            return

        tool_name = "browser" if self.has_tool("browser") else "whatweb"
        tool_result = await self.run_tool(tool_name, target)
        if tool_result is None or not tool_result.success:
            results["context_updates"]["technology_status"] = "detection_unavailable"
            return

        for parsed in tool_result.findings:
            finding = {
                "type": "technology",
                "title": parsed.get("title", f"Technology detected on {target}"),
                "severity": "Informational",
                "target": target,
                "confidence": parsed.get("confidence", "medium"),
                "source": f"tool:{tool_name}",
                "description": parsed.get("summary", "Technology observed during fingerprinting."),
                "remediation": "Ensure all detected technologies are patched and supported.",
                "raw": parsed,
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            self.technologies.append(parsed)

        results["context_updates"]["technologies"] = self.technologies
        results["context_updates"]["technology_status"] = "completed"
