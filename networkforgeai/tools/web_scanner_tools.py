"""Web application security scanning tools."""

import logging
import re
import tempfile
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel

logger = logging.getLogger(__name__)


class NiktoTool(BaseTool):
    """Nikto web server scanner."""

    name = "nikto"
    description = "Web server scanner for dangerous files/CGIs"
    category = ToolCategory.WEB_SCAN
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = False

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "port": None,
            "ssl": False,
            "tuning": "1",  # Default: Interesting File / Seen in Logs
            "maxtime": None,
            "output_format": "json",
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build nikto command."""
        opts = {**self.default_options, **(options or {})}

        cmd = ["nikto", "-host", target]

        # Port specification
        if opts.get("port"):
            cmd.extend(["-port", str(opts["port"])])

        # SSL
        if opts.get("ssl"):
            cmd.append("-ssl")

        # Tuning options
        if opts.get("tuning"):
            cmd.extend(["-Tuning", opts["tuning"]])

        # Max time
        if opts.get("maxtime"):
            cmd.extend(["-maxtime", str(opts["maxtime"])])

        # Output format
        output_format = opts.get("output_format", "json")
        if output_format == "json":
            cmd.extend(["-Format", "json", "-output", "-"])

        return cmd

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse nikto JSON output."""
        findings = []

        try:
            import json

            # Try to parse as JSON
            data = json.loads(stdout)

            # Nikto JSON structure varies by version
            vulns = data.get("vulnerabilities", [])

            for vuln in vulns:
                finding = {
                    "type": "web_vulnerability",
                    "method": vuln.get("method", "GET"),
                    "url": vuln.get("url", ""),
                    "description": vuln.get("description", ""),
                    "reference": vuln.get("references", []),
                    "confidence": "medium",
                    "summary": vuln.get("description", "")[:200],
                }

                # Extract CVE if present
                refs = vuln.get("references", [])
                cve_match = re.search(r"(CVE-\d{4}-\d+)", str(refs))
                if cve_match:
                    finding["cve"] = cve_match.group(1)

                findings.append(finding)

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse nikto output: {e}")

            # Fallback: regex-based parsing of text output
            lines = stdout.split("\n")
            for line in lines:
                if "+ " in line and ("/" in line):
                    findings.append(
                        {"type": "web_finding", "description": line.strip(), "confidence": "low"}
                    )

        return findings


class OWASPZAPTool(BaseTool):
    """OWASP ZAP security scanner."""

    name = "owasp-zap"
    description = "OWASP Zed Attack Proxy - web application scanner"
    category = ToolCategory.WEB_SCAN
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = False

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.zap_host = "localhost"
        self.zap_port = 8080
        self.api_key = ""
        self.default_options = {
            "scan_type": "quick",  # quick, full, api
            "spider": True,
            "ajax_spider": False,
            "active_scan": True,
            "max_duration": 60,  # minutes
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Build ZAP CLI command.

        Note: For full integration, use ZAP API instead of CLI.
        This is a simplified CLI wrapper.
        """
        opts = {**self.default_options, **(options or {})}

        cmd = [
            "zap-cli",
            "--api-key",
            self.api_key if self.api_key else "unused",
            "quick-scan",
            "--spider" if opts.get("spider") else "--no-spider",
            "-t",
            str(opts.get("max_duration", 60)),
        ]

        if opts.get("active_scan"):
            cmd.append("--scanners")
            cmd.append("all")

        cmd.append(target)

        return cmd

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse ZAP alert output."""
        findings = []

        # Parse ZAP alert format
        alert_pattern = r"\[(HIGH|MEDIUM|LOW|INFORMATIONAL)\]\s+(.+?)\s+URL:\s+(\S+)"

        matches = re.finditer(alert_pattern, stdout)

        for match in matches:
            risk, description, url = match.groups()

            finding = {
                "type": "web_vulnerability",
                "risk_level": risk.lower(),
                "url": url,
                "description": description.strip(),
                "confidence": "high" if risk == "HIGH" else "medium",
                "summary": description.strip()[:200],
            }

            findings.append(finding)

        return findings


class SQLMapTool(BaseTool):
    """SQLMap SQL injection testing tool."""

    name = "sqlmap"
    description = "Automatic SQL injection and database takeover tool"
    category = ToolCategory.WEB_SCAN
    risk_level = ToolRiskLevel.HIGH
    requires_approval = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "level": 1,  # 1-5, higher = more tests
            "risk": 1,  # 1-3, higher = more risky tests
            "techniques": "BEUSTQ",  # SQL injection techniques
            "threads": 1,
            "timeout": 30,
            "batch": True,  # Non-interactive mode
            "forms": False,  # Test form parameters
            "crawl": 0,  # Crawl depth
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """Build sqlmap command."""
        opts = {**self.default_options, **(options or {})}

        cmd = ["sqlmap"]

        # Target specification
        if target.startswith("http"):
            cmd.extend(["-u", target])
        else:
            # Assume it's a request file or other format
            cmd.extend(["-u", target])

        # Level and risk
        cmd.extend(["--level", str(opts.get("level", 1))])
        cmd.extend(["--risk", str(opts.get("risk", 1))])

        # Techniques
        cmd.extend(["--technique", opts.get("techniques", "BEUSTQ")])

        # Performance
        cmd.extend(["--threads", str(opts.get("threads", 1))])
        cmd.extend(["--timeout", str(opts.get("timeout", 30))])

        # Batch mode (non-interactive)
        if opts.get("batch", True):
            cmd.append("--batch")

        # Forms
        if opts.get("forms"):
            cmd.append("--forms")

        # Crawl
        crawl_depth = opts.get("crawl", 0)
        if crawl_depth > 0:
            cmd.extend(["--crawl", str(crawl_depth)])

        # Output format
        cmd.extend(["--output-dir", tempfile.gettempdir() + "/sqlmap_output"])

        return cmd

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse sqlmap output for SQL injection findings."""
        findings = []

        # Look for injection point indicators
        injection_patterns = [
            r"Parameter.*is vulnerable\.? (.+?)",
            r"(SQL injection|boolean-blind|time-blind|error-based|UNION query).*detected",
            r"back-end DBMS:\s*(\S+)",
        ]

        for pattern in injection_patterns:
            matches = re.finditer(pattern, stdout, re.IGNORECASE)
            for match in matches:
                finding = {
                    "type": "sql_injection",
                    "description": match.group(0).strip(),
                    "confidence": "high",
                    "severity": "critical",
                    "summary": "SQL Injection vulnerability detected",
                }

                # Try to extract parameter name
                param_match = re.search(r'Parameter [`\'"]?(\w+)[`\'"]?', match.group(0))
                if param_match:
                    finding["parameter"] = param_match.group(1)

                # Try to extract DBMS
                dbms_match = re.search(r"DBMS:\s*(\w+)", stdout)
                if dbms_match:
                    finding["dbms"] = dbms_match.group(1)

                findings.append(finding)

        return findings
