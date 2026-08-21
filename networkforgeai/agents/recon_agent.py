"""
Reconnaissance Agent - Passive and active information gathering

Capabilities:
- Subdomain enumeration
- Port scanning (non-intrusive)
- Service fingerprinting
- Technology stack detection
- OSINT collection

All active scanning requires human approval.
"""

from typing import Any, Dict, List

from ..core.approval_gateway import RiskLevel
from ..core.base_agent import AgentStatus, BaseAgent


class ReconAgent(BaseAgent):
    """
    AI-powered reconnaissance agent for information gathering.

    Operates in two modes:
    - Passive: OSINT, public records, DNS lookups (auto-approved in auto-low mode)
    - Active: Port scanning, service probing (requires explicit approval)
    """

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
        """
        Execute reconnaissance tasks.

        Tasks can include:
        - "enumerate_subdomains": Find subdomains of target domain
        - "scan_ports": Scan for open ports (requires approval)
        - "fingerprint_services": Identify running services (requires approval)
        - "detect_technologies": Identify web technologies
        """
        self.current_task = task
        self.status = AgentStatus.RUNNING

        results = {"task": task, "findings": [], "context_updates": {}}

        try:
            if task == "enumerate_subdomains":
                await self._enumerate_subdomains(context, results)
            elif task == "scan_ports":
                await self._scan_ports(context, results)
            elif task == "fingerprint_services":
                await self._fingerprint_services(context, results)
            elif task == "detect_technologies":
                await self._detect_technologies(context, results)
            else:
                # General recon - run all applicable tasks
                await self._enumerate_subdomains(context, results)
                await self._detect_technologies(context, results)

        except Exception as e:
            results["error"] = str(e)
            self.status = AgentStatus.ERROR

        finally:
            self.status = AgentStatus.IDLE
            from datetime import datetime

            self.last_active = datetime.utcnow()

        return results

    async def _enumerate_subdomains(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Enumerate subdomains using passive techniques."""
        target = context.get("target", "")
        if not target:
            return

        # Simulated subdomain enumeration
        # In production, this would integrate with tools like:
        # - theHarvester
        # - Sublist3r
        # - Amass (passive mode)
        # - Certificate transparency logs

        print(f"[ReconAgent] Enumerating subdomains for {target}...")

        # Placeholder: In real implementation, call actual tools
        discovered = [f"www.{target}", f"mail.{target}", f"api.{target}"]

        for subdomain in discovered:
            finding = {
                "type": "subdomain",
                "title": f"Discovered Subdomain: {subdomain}",
                "severity": "Informational",
                "target": subdomain,
                "description": f"Subdomain {subdomain} discovered during reconnaissance.",
                "poc": f"nslookup {subdomain}",
                "reproduction_steps": f"1. Run: nslookup {subdomain}\n2. Verify DNS resolution",
                "remediation": "Ensure all subdomains are documented and secured.",
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            self.discovered_hosts.append(subdomain)

        results["context_updates"]["discovered_hosts"] = self.discovered_hosts

    async def _scan_ports(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Scan for open ports (requires human approval)."""
        target = context.get("target", "")
        if not target:
            return

        # Request approval before active scanning
        approved, _ = await self.request_approval(
            action_type="port_scan",
            description=f"Perform TCP port scan on {target} to identify open services",
            target=target,
            risk_level=RiskLevel.LOW,  # Non-intrusive SYN scan
            details={"scan_type": "TCP SYN", "ports": "1-1000", "rate_limit": "100 packets/sec"},
            timeout_seconds=600,
        )

        if not approved:
            print("[ReconAgent] Port scan rejected by human operator")
            return

        print(f"[ReconAgent] Performing approved port scan on {target}...")

        # Simulated port scan
        # In production, integrate with Nmap or masscan
        open_ports = [
            {"port": 80, "protocol": "tcp", "service": "http"},
            {"port": 443, "protocol": "tcp", "service": "https"},
            {"port": 22, "protocol": "tcp", "service": "ssh"},
        ]

        for port_info in open_ports:
            finding = {
                "type": "open_port",
                "title": f"Open Port: {port_info['port']}/{port_info['protocol']} ({port_info['service']})",
                "severity": "Informational",
                "target": target,
                "description": f"Port {port_info['port']} is open running {port_info['service']}",
                "poc": f"nc -zv {target} {port_info['port']}",
                "reproduction_steps": f"1. Run: nc -zv {target} {port_info['port']}\n2. Observe connection success",
                "remediation": "Ensure the service is necessary and properly secured.",
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            self.discovered_ports.append({**port_info, "host": target})

        results["context_updates"]["discovered_ports"] = self.discovered_ports

    async def _fingerprint_services(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Fingerprint running services (requires approval)."""
        ports = context.get("discovered_ports", [])
        if not ports:
            return

        # Request approval
        approved, _ = await self.request_approval(
            action_type="service_fingerprinting",
            description="Perform service version detection on discovered ports",
            target=context.get("target", ""),
            risk_level=RiskLevel.LOW,
            details={"technique": "Banner grabbing, protocol handshake analysis"},
            timeout_seconds=600,
        )

        if not approved:
            return

        print("[ReconAgent] Performing approved service fingerprinting...")

        # Simulated fingerprinting
        for port_info in ports:
            version_info = f"{port_info.get('service', 'unknown')} v1.0"
            finding = {
                "type": "service_version",
                "title": f"Service Version Detected: {version_info}",
                "severity": "Informational",
                "target": port_info.get("host", ""),
                "description": f"Service version identified on port {port_info['port']}",
                "poc": f"curl -v http://{port_info.get('host', '')}:{port_info['port']}/",
                "reproduction_steps": "1. Connect to service\n2. Analyze banner/headers\n3. Identify version",
                "remediation": "Keep services updated to latest versions.",
            }
            self.add_finding(finding)
            results["findings"].append(finding)

    async def _detect_technologies(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Detect web technologies (passive, no approval needed in auto-low mode)."""
        hosts = context.get("discovered_hosts", [])
        target = context.get("target", "")

        if not hosts and target:
            hosts = [target]

        print("[ReconAgent] Detecting web technologies...")

        # Simulated technology detection
        # In production, integrate with Wappalyzer or WhatWeb
        technologies = [
            {"name": "Nginx", "category": "Web Server", "version": "1.18.0"},
            {"name": "React", "category": "JavaScript Framework", "version": "18.2.0"},
            {"name": "Node.js", "category": "Runtime", "version": "18.x"},
        ]

        for host in hosts:
            for tech in technologies:
                finding = {
                    "type": "technology",
                    "title": f"Technology Detected: {tech['name']} {tech.get('version', '')}",
                    "severity": "Informational",
                    "target": host,
                    "description": f"{tech['category']} detected: {tech['name']}",
                    "poc": f"Check HTTP headers or JS files on http://{host}",
                    "reproduction_steps": f"1. Visit http://{host}\n2. Inspect headers/source\n3. Identify {tech['name']}",
                    "remediation": "Ensure all technologies are patched and up to date.",
                }
                self.add_finding(finding)
                results["findings"].append(finding)
                self.technologies.append({**tech, "host": host})

        results["context_updates"]["technologies"] = self.technologies
