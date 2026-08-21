"""Nmap network scanner integration."""

from typing import Any, Dict, List, Optional
import re
import logging
from .base_tool import BaseTool, ToolCategory, ToolRiskLevel, ToolResult

logger = logging.getLogger(__name__)


class NmapTool(BaseTool):
    """Nmap network scanning tool."""
    
    name = "nmap"
    description = "Network exploration and security auditing tool"
    category = ToolCategory.NETWORK_SCAN
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = False
    
    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "ports": None,  # e.g., "1-1000" or "80,443,8080"
            "scan_type": "-sS",  # SYN scan by default
            "version_detection": True,
            "os_detection": False,
            "script_scan": False,
            "timing": "-T4",
            "output_format": "xml"
        }
    
    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build nmap command."""
        opts = {**self.default_options, **(options or {})}
        
        cmd = ["nmap"]
        
        # Scan type
        cmd.append(opts.get("scan_type", "-sS"))
        
        # Timing template
        cmd.append(opts.get("timing", "-T4"))
        
        # Port specification
        if opts.get("ports"):
            cmd.extend(["-p", str(opts["ports"])])
        else:
            cmd.append("--top-ports")
            cmd.append(str(opts.get("top_ports", 1000)))
        
        # Version detection
        if opts.get("version_detection"):
            cmd.append("-sV")
        
        # OS detection (requires root)
        if opts.get("os_detection"):
            cmd.append("-O")
        
        # Script scan
        if opts.get("script_scan"):
            scripts = opts.get("scripts", "default")
            cmd.extend(["-sC", f"--script={scripts}"])
        
        # Output format
        output_format = opts.get("output_format", "xml")
        if output_format == "xml":
            cmd.extend(["-oX", "-"])  # Output to stdout
        elif output_format == "grepable":
            cmd.extend(["-oG", "-"])
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse nmap output to extract hosts, ports, and services."""
        findings = []
        
        # Simple regex parsing for open ports
        # Pattern: <port protocol="tcp" portid="80"><state state="open".../><service name="http".../>
        port_pattern = r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?<service name="([^"]*)"(?: version="([^"]*)")?'
        
        matches = re.finditer(port_pattern, stdout, re.DOTALL)
        
        for match in matches:
            protocol, port, state, service, version = match.groups()
            
            if state == "open":
                finding = {
                    "type": "open_port",
                    "protocol": protocol,
                    "port": int(port),
                    "state": state,
                    "service": service or "unknown",
                    "version": version or None,
                    "confidence": "high"
                }
                
                # Generate a summary
                if version:
                    finding["summary"] = f"Open port {port}/{protocol}: {service} ({version})"
                else:
                    finding["summary"] = f"Open port {port}/{protocol}: {service}"
                
                findings.append(finding)
        
        # Parse host information
        host_pattern = r'<host[^>]*>.*?<address addr="([^"]+)" addrtype="ipv4"/>.*?<status state="(\w+)"'
        host_matches = re.finditer(host_pattern, stdout, re.DOTALL)
        
        for match in host_matches:
            ip, status = match.groups()
            if status == "up":
                findings.append({
                    "type": "host_up",
                    "ip": ip,
                    "status": status,
                    "summary": f"Host {ip} is up"
                })
        
        return findings


class MasscanTool(BaseTool):
    """Masscan fast port scanner."""
    
    name = "masscan"
    description = "Fastest Internet-scale port scanner"
    category = ToolCategory.NETWORK_SCAN
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = False
    
    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "ports": "1-65535",
            "rate": "1000",  # packets per second
            "wait": "10"  # wait time after scan
        }
    
    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build masscan command."""
        opts = {**self.default_options, **(options or {})}
        
        cmd = [
            "masscan",
            "--ports", opts["ports"],
            "--rate", opts["rate"],
            "--wait", opts["wait"],
            "--output-format", "json"
        ]
        
        cmd.append(target)
        
        return cmd
    
    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse masscan JSON output."""
        findings = []
        
        try:
            import json
            # masscan outputs JSON array
            results = json.loads(stdout)
            
            for result in results:
                if isinstance(result, dict) and result.get("ip") and result.get("ports"):
                    ip = result["ip"]
                    for port_info in result.get("ports", []):
                        port = port_info.get("port")
                        protocol = port_info.get("proto", "tcp")
                        
                        findings.append({
                            "type": "open_port",
                            "ip": ip,
                            "protocol": protocol,
                            "port": port,
                            "state": "open",
                            "summary": f"Open port {port}/{protocol} on {ip}"
                        })
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse masscan output: {e}")
        
        return findings
