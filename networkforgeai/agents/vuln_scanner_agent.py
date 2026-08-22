"""
Vulnerability Scanner Agent - Identifies and validates vulnerabilities

This agent does not fabricate vulnerabilities. It operates in three honest modes:

1. Tool-backed validation: when a matching tool wrapper (e.g. ``sqlmap``) is
   registered, it runs the tool through the approval gateway and reports only
   what the tool actually found.
2. LLM triage: when a model is configured but no active-testing tool is
   available, it emits advisory *hypotheses* tagged ``source="llm_hypothesis"``
   and ``validated=False`` — never confirmed findings.
3. Otherwise it returns no findings and records an explicit ``*_status`` note.

All active exploitation attempts require explicit human approval, enforced by
the tool wrappers via the shared gateway.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..core.base_agent import AgentStatus, BaseAgent


class VulnerabilityScannerAgent(BaseAgent):
    """Vulnerability agent that validates with real tools or advises via the LLM."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="VulnScannerAgent", **kwargs)
        self.vulnerabilities_found: List[Dict[str, Any]] = []

    def get_capabilities(self) -> List[str]:
        return [
            "vulnerability_scanning",
            "sql_injection_testing",
            "xss_testing",
            "ssrf_testing",
            "authentication_testing",
            "business_logic_testing",
        ]

    async def execute(self, task: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute vulnerability analysis tasks against authorized targets."""
        self.current_task = task
        self.status = AgentStatus.RUNNING

        results: Dict[str, Any] = {"task": task, "findings": [], "context_updates": {}}

        try:
            if task == "scan_sql_injection":
                await self._scan_sql_injection(context, results)
            elif task in {"scan_xss", "scan_ssrf", "scan_auth_bypass"}:
                await self._triage_class(task, context, results)
            else:
                await self._scan_sql_injection(context, results)
                await self._triage_class("scan_xss", context, results)
                await self._triage_class("scan_ssrf", context, results)

        except Exception as e:  # noqa: BLE001 - reported as task error, never fatal
            results["error"] = str(e)
            self.status = AgentStatus.ERROR

        finally:
            self.status = AgentStatus.IDLE

        return results

    def _target_urls(self, context: Dict[str, Any]) -> List[str]:
        urls = context.get("discovered_urls", [])
        if urls:
            return list(urls)
        target = context.get("target")
        return [f"http://{target}/"] if target else []

    async def _scan_sql_injection(self, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        """Validate SQL injection using the ``sqlmap`` wrapper, or advise via LLM."""
        urls = self._target_urls(context)
        if not urls:
            results["context_updates"]["sql_injection_status"] = "no_target"
            return

        if self.has_tool("sqlmap"):
            # The sqlmap wrapper is HIGH risk and self-gates approval via the gateway.
            try:
                tool_result = await self.run_tool("sqlmap", urls[0])
            except PermissionError:
                results["context_updates"]["sql_injection_status"] = "rejected"
                return
            if tool_result is None or not tool_result.success:
                results["context_updates"]["sql_injection_status"] = "scan_failed"
                return
            emitted = 0
            for parsed in tool_result.findings:
                finding = self._sqli_finding(urls[0], parsed)
                self.add_finding(finding)
                results["findings"].append(finding)
                self.vulnerabilities_found.append(finding)
                emitted += 1
            results["context_updates"]["sql_injection_status"] = (
                "confirmed" if emitted else "not_detected"
            )
            results["context_updates"]["sql_injection_vulns"] = self.vulnerabilities_found
            return

        # No active-testing tool: fall back to advisory hypotheses only.
        hypotheses = await self.llm_hypotheses(
            "Given the reconnaissance evidence, list plausible SQL injection hypotheses to "
            "validate manually. Do not claim confirmation.",
            context,
        )
        results["findings"].extend(hypotheses)
        for item in hypotheses:
            self.add_finding(item)
        results["context_updates"]["sql_injection_status"] = (
            "hypotheses_only" if hypotheses else "no_tool_or_model"
        )

    async def _triage_class(
        self, task: str, context: Dict[str, Any], results: Dict[str, Any]
    ) -> None:
        """Produce advisory hypotheses for a vuln class with no bundled active tool."""
        vuln_class = {
            "scan_xss": "cross-site scripting (XSS)",
            "scan_ssrf": "server-side request forgery (SSRF)",
            "scan_auth_bypass": "authentication/authorization bypass",
        }[task]
        status_key = f"{task.removeprefix('scan_')}_status"

        if not self._target_urls(context):
            results["context_updates"][status_key] = "no_target"
            return

        hypotheses = await self.llm_hypotheses(
            f"Given the reconnaissance evidence, list plausible {vuln_class} hypotheses that a "
            "human should validate manually. Base them only on the evidence; do not confirm.",
            context,
        )
        results["findings"].extend(hypotheses)
        for item in hypotheses:
            self.add_finding(item)
        results["context_updates"][status_key] = (
            "hypotheses_only" if hypotheses else "no_tool_or_model"
        )

    @staticmethod
    def _sqli_finding(url: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
        parameter = parsed.get("parameter", "unknown")
        return {
            "type": "sql_injection",
            "title": f"SQL Injection in {parameter} parameter",
            "severity": "Critical",
            "category": "Injection",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "cvss_score": 9.8,
            "target": url,
            "confidence": "high",
            "source": "tool:sqlmap",
            "validated": True,
            "description": (
                f"sqlmap reported an injectable '{parameter}' parameter at {url}. "
                "Confirm and scope the impact before reporting."
            ),
            "poc": parsed.get("poc", f"sqlmap -u {url} --batch"),
            "reproduction_steps": (
                f"1. Run: sqlmap -u {url} --batch\n"
                "2. Review the confirmed injection point and technique in the sqlmap log"
            ),
            "remediation": (
                "1. Use parameterized queries (prepared statements)\n"
                "2. Validate and sanitize input\n"
                "3. Apply least privilege to the database account"
            ),
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
            "raw": parsed,
        }
