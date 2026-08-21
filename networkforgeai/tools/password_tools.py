"""Password attack and credential testing tools."""

import logging
import re
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel

logger = logging.getLogger(__name__)


class HydraTool(BaseTool):
    """Hydra online password cracking tool."""

    name = "hydra"
    description = "Fast and flexible online brute-force password cracker"
    category = ToolCategory.PASSWORD_ATTACK
    risk_level = ToolRiskLevel.HIGH
    requires_approval = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "username": None,
            "userlist": None,
            "password": None,
            "passlist": None,
            "service": "ssh",
            "port": None,
            "threads": 4,
            "timeout": 30,
            "attempts": 3,
            "verbose": False,
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build hydra command."""
        opts = {**self.default_options, **(options or {})}

        cmd = ["hydra"]

        # Username specification
        if opts.get("username"):
            cmd.extend(["-l", opts["username"]])
        elif opts.get("userlist"):
            cmd.extend(["-L", opts["userlist"]])
        else:
            raise ValueError("Either username or userlist must be specified")

        # Password specification
        if opts.get("password"):
            cmd.extend(["-p", opts["password"]])
        elif opts.get("passlist"):
            cmd.extend(["-P", opts["passlist"]])
        else:
            raise ValueError("Either password or passlist must be specified")

        # Service and port
        service = opts.get("service", "ssh")
        port = opts.get("port")

        if port:
            cmd.extend(["-s", str(port)])

        # Performance options
        cmd.extend(["-t", str(opts.get("threads", 4))])
        cmd.extend(["-w", str(opts.get("timeout", 30))])
        cmd.extend(["-f"])  # Exit after first found credential

        # Verbose output
        if opts.get("verbose"):
            cmd.append("-v")

        # Target and service
        cmd.append(target)
        cmd.append(service)

        return cmd

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse hydra output for successful credentials."""
        findings = []

        # Pattern: [SERVICE]://[USER:PASS@]HOST[:PORT]/[PATH]
        success_pattern = (
            r"\[(\w+)\]\/(\w+).*host:\s*([^\s]+)\s+login:\s*([^\s]+)\s+password:\s*([^\s]+)"
        )

        matches = re.finditer(success_pattern, stdout, re.IGNORECASE)

        for match in matches:
            service, protocol, host, username, password = match.groups()

            finding = {
                "type": "credential_found",
                "service": service,
                "protocol": protocol,
                "host": host,
                "username": username,
                "password": password,
                "confidence": "high",
                "severity": "critical",
                "summary": f"Valid credentials found: {username}:{password}@{host}",
            }

            findings.append(finding)

        # Also check for simpler patterns
        simple_pattern = r"login:\s*(\S+)\s+password:\s*(\S+)"
        simple_matches = re.finditer(simple_pattern, stdout)

        for match in simple_matches:
            username, password = match.groups()
            finding = {
                "type": "credential_found",
                "username": username,
                "password": password,
                "confidence": "high",
                "severity": "critical",
                "summary": f"Valid credentials found: {username}:{password}",
            }

            # Avoid duplicates
            if not any(
                f.get("username") == username and f.get("password") == password for f in findings
            ):
                findings.append(finding)

        return findings


class CrackMapExecTool(BaseTool):
    """CrackMapExec network exploitation tool."""

    name = "crackmapexec"
    description = "Swiss army knife for pentesting networks (SMB/LDAP/WinRM)"
    category = ToolCategory.POST_EXPLOITATION
    risk_level = ToolRiskLevel.HIGH
    requires_approval = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "protocol": "smb",
            "username": None,
            "password": None,
            "hashes": None,
            "local_auth": False,
            "command": None,
            "shares": False,
            "users": False,
            "passes": False,
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build crackmapexec command."""
        opts = {**self.default_options, **(options or {})}

        protocol = opts.get("protocol", "smb")
        cmd = ["crackmapexec", protocol]

        # Add target(s)
        cmd.append(target)

        # Authentication
        if opts.get("username") and opts.get("password"):
            cmd.extend(["-u", opts["username"], "-p", opts["password"]])
        elif opts.get("username") and opts.get("hashes"):
            cmd.extend(["-u", opts["username"], "-H", opts["hashes"]])

        # Local authentication
        if opts.get("local_auth"):
            cmd.append("--local-auth")

        # Modules
        if opts.get("shares"):
            cmd.append("--shares")
        if opts.get("users"):
            cmd.append("--users")
        if opts.get("passes"):
            cmd.append("--pass-pol")

        # Command execution
        if opts.get("command"):
            cmd.extend(["-x", opts["command"]])

        return cmd

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse crackmapexec output."""
        findings = []

        # Look for successful authentications
        auth_pattern = r"\[(\+\+)\]\s+(\S+):(\d+)\s+(\S+):(\S+)"

        matches = re.finditer(auth_pattern, stdout)

        for match in matches:
            status, host, port, username, domain = match.groups()

            finding = {
                "type": "successful_auth",
                "host": host,
                "port": int(port),
                "username": username,
                "domain": domain,
                "status": "success",
                "confidence": "high",
                "summary": f"Successful authentication to {host}:{port} as {username}",
            }

            findings.append(finding)

        # Look for shares enumeration
        share_pattern = r"(READ|WRITE)\s+(.+)"
        share_matches = re.finditer(share_pattern, stdout)

        for match in share_matches:
            access, share_name = match.groups()

            finding = {
                "type": "share_access",
                "access_level": access,
                "share_name": share_name.strip(),
                "confidence": "medium",
                "summary": f"{access} access to share: {share_name.strip()}",
            }

            findings.append(finding)

        return findings


class ImpacketTools(BaseTool):
    """Impacket suite of Python tools for network protocols."""

    name = "impacket"
    description = "Collection of Python classes for working with network protocols"
    category = ToolCategory.POST_EXPLOITATION
    risk_level = ToolRiskLevel.HIGH
    requires_approval = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.available_tools = {
            "smbclient": "SMB client",
            "secretsdump": "Dump secrets from remote systems",
            "psexec": "Execute commands via SMB",
            "wmiexec": "Execute commands via WMI",
            "rpcclient": "RPC client",
            "lookupsid": "SID enumeration",
            "samrdump": "SAMR dump",
        }
        self.default_options = {
            "tool": "smbclient",
            "username": "",
            "password": "",
            "hashes": "",
            "domain": "",
            "no_pass": False,
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build impacket tool command."""
        opts = {**self.default_options, **(options or {})}

        tool = opts.get("tool", "smbclient")

        if tool not in self.available_tools:
            raise ValueError(
                f"Unknown impacket tool: {tool}. Available: {list(self.available_tools.keys())}"
            )

        cmd = [tool]

        # Authentication
        if opts.get("username"):
            creds = f"{opts['username']}"
            if opts.get("password"):
                creds += f":{opts['password']}"
            cmd.extend(["-credentials", creds])
        elif opts.get("hashes"):
            cmd.extend(["-hashes", opts["hashes"]])
        elif opts.get("no_pass"):
            cmd.append("-no-pass")

        # Domain
        if opts.get("domain"):
            cmd.extend(["-domain", opts["domain"]])

        # Target
        cmd.append(target)

        return cmd

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse impacket tool output."""
        findings = []

        # Generic parsing - specific implementations would vary by tool
        # Look for successful connections
        if "Session established" in stdout or "Connected" in stdout:
            findings.append(
                {
                    "type": "connection_success",
                    "description": "Successfully connected to target",
                    "confidence": "high",
                }
            )

        # Look for enumerated users
        user_pattern = r"(\S+)\\(\S+)\s+\((.*?)\)"
        user_matches = re.finditer(user_pattern, stdout)

        for match in user_matches:
            domain, username, description = match.groups()

            finding = {
                "type": "user_enumerated",
                "domain": domain,
                "username": username,
                "description": description,
                "confidence": "high",
                "summary": f"User enumerated: {domain}\\{username}",
            }

            findings.append(finding)

        return findings
