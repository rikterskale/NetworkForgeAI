"""Metasploit Framework integration (sandboxed, HITL-required)."""

import re
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel


class MetasploitTool(BaseTool):
    """Metasploit Framework console wrapper.

    Commands are built as ``msfconsole -q -x`` resource one-liners and executed
    inside the Docker sandbox by ``BaseTool.execute``. Exploitation is
    CRITICAL-risk and always requires explicit human approval through the
    gateway; the tool fails closed without an attached gateway.
    """

    name = "metasploit"
    description = "Metasploit Framework exploitation console (HITL required)"
    category = ToolCategory.EXPLOITATION
    risk_level = ToolRiskLevel.CRITICAL
    requires_approval = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options: Dict[str, Any] = {
            "module": None,  # e.g. "exploit/windows/smb/ms17_010_eternalblue"
            "payload": None,  # e.g. "linux/x64/meterpreter/reverse_tcp"
            "set_options": {},  # extra `set KEY VALUE` pairs, e.g. {"LPORT": 4444}
            "check_only": False,  # run the module's `check` instead of exploiting
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}

        module = opts.get("module")
        if not module:
            raise ValueError("metasploit requires a 'module' option")

        script_lines = [f"use {module}", "setg ExitOnSession false"]
        if opts.get("check_only"):
            script_lines.append("set ValidateTarget true")
        script_lines.append(f"set RHOSTS {target}")
        payload = opts.get("payload")
        if payload:
            script_lines.extend([f"set PAYLOAD {payload}"])
        for key, value in sorted((opts.get("set_options") or {}).items()):
            script_lines.append(f"set {key} {value}")
        script_lines.append("check" if opts.get("check_only") else "run")
        script_lines.append("exit")

        return ["msfconsole", "-q", "-x", "; ".join(script_lines)]

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Extract session openings, vuln confirmations, and errors from console output."""
        findings: List[Dict[str, Any]] = []

        for match in re.finditer(r"Meterpreter session (\d+) opened", stdout):
            findings.append(
                {
                    "type": "session_opened",
                    "session_id": int(match.group(1)),
                    "summary": f"Meterpreter session {match.group(1)} opened",
                    "confidence": "high",
                }
            )

        for match in re.finditer(
            r"(\S+://\S+|\b[\w.-]+:\d+)\s+-\s+.*(Vulnerable|vulnerable)", stdout
        ):
            findings.append(
                {
                    "type": "confirmed_vulnerability",
                    "target": match.group(1),
                    "summary": f"Module check reports vulnerable: {match.group(0).strip()}",
                    "confidence": "high",
                }
            )

        if re.search(r"\b(not vulnerable|Could not connect)\b", stdout + stderr, re.IGNORECASE):
            findings.append(
                {
                    "type": "module_check_negative",
                    "summary": "Module check did not confirm vulnerability or could not connect",
                    "confidence": "medium",
                }
            )

        return findings
