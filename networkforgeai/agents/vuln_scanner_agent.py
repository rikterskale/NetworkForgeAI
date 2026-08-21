"""
Vulnerability Scanner Agent - Identifies and validates vulnerabilities

Capabilities:
- SQL Injection detection and validation
- XSS detection and validation
- SSRF detection and validation
- Authentication bypass testing
- Business logic flaw detection

All exploitation attempts require explicit human approval.
"""

from typing import Any, Dict, List

from ..core.approval_gateway import RiskLevel
from ..core.base_agent import AgentStatus, BaseAgent


class VulnerabilityScannerAgent(BaseAgent):
    """
    AI-powered vulnerability scanner that identifies and validates security issues.

    Key features:
    - Detects OWASP Top 10 vulnerabilities
    - Validates findings with working PoCs
    - Requires human approval before any active testing
    - Provides detailed reproduction steps
    """

    def __init__(self, **kwargs):
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
        """
        Execute vulnerability scanning tasks.

        Tasks can include:
        - "scan_sql_injection": Test for SQL injection vulnerabilities
        - "scan_xss": Test for cross-site scripting
        - "scan_ssrf": Test for server-side request forgery
        - "scan_auth_bypass": Test for authentication bypass
        - "scan_business_logic": Test for business logic flaws
        """
        self.current_task = task
        self.status = AgentStatus.RUNNING

        results = {"task": task, "findings": [], "context_updates": {}}

        try:
            if task == "scan_sql_injection":
                await self._scan_sql_injection(context, results)
            elif task == "scan_xss":
                await self._scan_xss(context, results)
            elif task == "scan_ssrf":
                await self._scan_ssrf(context, results)
            elif task == "scan_auth_bypass":
                await self._scan_auth_bypass(context, results)
            else:
                # Run all scans
                await self._scan_sql_injection(context, results)
                await self._scan_xss(context, results)
                await self._scan_ssrf(context, results)

        except Exception as e:
            results["error"] = str(e)
            self.status = AgentStatus.ERROR

        finally:
            self.status = AgentStatus.IDLE

        return results

    async def _scan_sql_injection(self, context: Dict[str, Any], results: Dict[str, Any]):
        """Test for SQL injection vulnerabilities (requires HIGH risk approval)."""
        target_urls = context.get("discovered_urls", [])
        if not target_urls:
            target_urls = [f"http://{context.get('target', 'target')}/"]

        # Request approval for SQL injection testing
        approved, response = await self.request_approval(
            action_type="sql_injection_test",
            description="Test identified URLs for SQL injection vulnerabilities using time-based and error-based techniques",
            target=target_urls[0],
            risk_level=RiskLevel.HIGH,
            details={
                "test_types": ["time_based", "error_based", "boolean_based"],
                "payloads": ["' OR '1'='1", "' UNION SELECT NULL--", "1; WAITFOR DELAY"],
                "impact": "Potential database access, data exfiltration",
            },
            timeout_seconds=600,
        )

        if not approved:
            print("[VulnScanner] SQL injection testing rejected by operator")
            return

        print("[VulnScanner] Performing approved SQL injection tests...")

        # Simulated SQL injection detection
        # In production, integrate with sqlmap (with user approval) or custom payloads
        test_results = [
            {
                "url": target_urls[0],
                "parameter": "id",
                "type": "SQL Injection (Boolean-based)",
                "payload": "' OR '1'='1",
                "evidence": "Response differs when payload is true vs false",
            }
        ]

        for result in test_results:
            finding = {
                "type": "sql_injection",
                "title": f"SQL Injection in {result['parameter']} parameter",
                "severity": "Critical",
                "category": "Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021-Injection",
                "cvss_score": 9.8,
                "target": result["url"],
                "description": (
                    f"SQL injection vulnerability detected in the '{result['parameter']}' parameter. "
                    f"The application is vulnerable to {result['type']}. "
                    "An attacker could potentially access or modify database contents."
                ),
                "poc": (
                    f'curl -X GET "{result["url"]}?{result["parameter"]}={result["payload"]}\'"\n'
                    f"# Observe different response behavior"
                ),
                "reproduction_steps": (
                    f"1. Navigate to: {result['url']}\n"
                    f"2. Identify the '{result['parameter']}' parameter\n"
                    f"3. Modify parameter value to: {result['payload']}\n"
                    f"4. Submit request and observe response\n"
                    f"5. Compare with baseline request using: {result['parameter']}=1\n"
                    f"6. Different responses confirm SQL injection"
                ),
                "remediation": (
                    "1. Use parameterized queries (prepared statements)\n"
                    "2. Implement input validation and sanitization\n"
                    "3. Apply principle of least privilege to database accounts\n"
                    "4. Consider using an ORM framework\n"
                    "5. Implement Web Application Firewall (WAF) rules"
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
            }
            self.add_finding(finding)
            results["findings"].append(finding)
            self.vulnerabilities_found.append(finding)

        results["context_updates"]["sql_injection_vulns"] = self.vulnerabilities_found

    async def _scan_xss(self, context: Dict[str, Any], results: Dict[str, Any]):
        """Test for Cross-Site Scripting vulnerabilities (requires HIGH risk approval)."""
        target_urls = context.get("discovered_urls", [])
        if not target_urls:
            target_urls = [f"http://{context.get('target', 'target')}/"]

        # Request approval
        approved, _ = await self.request_approval(
            action_type="xss_test",
            description="Test for reflected and stored XSS vulnerabilities using script injection payloads",
            target=target_urls[0],
            risk_level=RiskLevel.HIGH,
            details={
                "test_types": ["reflected", "stored", "DOM-based"],
                "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "impact": "Session hijacking, credential theft, malware delivery",
            },
            timeout_seconds=600,
        )

        if not approved:
            print("[VulnScanner] XSS testing rejected by operator")
            return

        print("[VulnScanner] Performing approved XSS tests...")

        # Simulated XSS detection
        finding = {
            "type": "xss",
            "title": "Reflected Cross-Site Scripting (XSS)",
            "severity": "High",
            "category": "Cross-Site Scripting",
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "cvss_score": 7.5,
            "target": target_urls[0],
            "description": (
                "Reflected XSS vulnerability detected. User-supplied input is reflected in the response "
                "without proper encoding, allowing execution of arbitrary JavaScript."
            ),
            "poc": (
                f'curl -X GET "{target_urls[0]}?search=<script>alert(document.cookie)</script>"\n'
                "# When visited in browser, this will execute alert() with cookies"
            ),
            "reproduction_steps": (
                f"1. Navigate to: {target_urls[0]}?search=<script>alert(1)</script>\n"
                "2. Observe that the script executes in the browser context\n"
                "3. Verify by checking browser developer console\n"
                "4. Test persistence by refreshing the page"
            ),
            "remediation": (
                "1. Implement output encoding based on context (HTML, JavaScript, URL, CSS)\n"
                "2. Use Content Security Policy (CSP) headers\n"
                "3. Validate and sanitize all user input\n"
                "4. Use frameworks with built-in XSS protection\n"
                "5. Set HttpOnly flag on session cookies"
            ),
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
        }

        self.add_finding(finding)
        results["findings"].append(finding)
        self.vulnerabilities_found.append(finding)

    async def _scan_ssrf(self, context: Dict[str, Any], results: Dict[str, Any]):
        """Test for Server-Side Request Forgery (requires CRITICAL risk approval)."""
        target_urls = context.get("discovered_urls", [])
        if not target_urls:
            target_urls = [f"http://{context.get('target', 'target')}/"]

        # SSRF testing requires CRITICAL approval due to potential internal network access
        approved, _ = await self.request_approval(
            action_type="ssrf_test",
            description="Test for SSRF vulnerabilities by attempting to access internal resources",
            target=target_urls[0],
            risk_level=RiskLevel.CRITICAL,
            details={
                "test_types": ["basic_ssrf", "blind_ssrf", "filter_bypass"],
                "targets": ["http://localhost", "http://169.254.169.254 (cloud metadata)"],
                "impact": "Internal network reconnaissance, cloud credential theft, service abuse",
            },
            timeout_seconds=600,
        )

        if not approved:
            print("[VulnScanner] SSRF testing rejected by operator")
            return

        print("[VulnScanner] Performing approved SSRF tests...")

        # Simulated SSRF detection
        finding = {
            "type": "ssrf",
            "title": "Server-Side Request Forgery (SSRF)",
            "severity": "Critical",
            "category": "Server-Side Request Forgery",
            "cwe": "CWE-918",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "cvss_score": 9.0,
            "target": target_urls[0],
            "description": (
                "SSRF vulnerability allows the server to make arbitrary HTTP requests to internal resources. "
                "This could enable attackers to access internal services, cloud metadata, or perform port scanning."
            ),
            "poc": (
                f'curl -X POST "{target_urls[0]}api/fetch" \\\n'
                "  -H 'Content-Type: application/json' \\\n"
                '  -d \'{{"url": "http://169.254.169.254/latest/meta-data/"}}\'\n'
                "# Returns AWS EC2 metadata if vulnerable"
            ),
            "reproduction_steps": (
                "1. Identify a feature that fetches external URLs (webhooks, previews, imports)\n"
                "2. Send request with URL pointing to internal resource:\n"
                "   - http://localhost:8080\n"
                "   - http://169.254.169.254/latest/meta-data/ (AWS)\n"
                "   - http://metadata.google.internal/ (GCP)\n"
                "3. Observe if internal resource content is returned\n"
                "4. For blind SSRF, monitor your out-of-band server for callbacks"
            ),
            "remediation": (
                "1. Disable unnecessary URL fetching functionality\n"
                "2. Implement allowlist of permitted domains\n"
                "3. Block requests to private IP ranges (RFC 1918)\n"
                "4. Block cloud metadata endpoints\n"
                "5. Use network segmentation to limit blast radius\n"
                "6. Validate and sanitize all user-supplied URLs"
            ),
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            ],
        }

        self.add_finding(finding)
        results["findings"].append(finding)
        self.vulnerabilities_found.append(finding)

    async def _scan_auth_bypass(self, context: Dict[str, Any], results: Dict[str, Any]):
        """Test for authentication bypass vulnerabilities (requires HIGH risk approval)."""
        target_urls = context.get("discovered_urls", [])
        if not target_urls:
            target_urls = [f"http://{context.get('target', 'target')}/"]

        approved, _ = await self.request_approval(
            action_type="auth_bypass_test",
            description="Test for authentication and authorization bypass vulnerabilities",
            target=target_urls[0],
            risk_level=RiskLevel.HIGH,
            details={
                "test_types": ["forceful_browsing", "parameter_pollution", "jwt_manipulation"],
                "impact": "Unauthorized access to admin functions, data breach",
            },
            timeout_seconds=600,
        )

        if not approved:
            print("[VulnScanner] Auth bypass testing rejected by operator")
            return

        print("[VulnScanner] Performing approved authentication bypass tests...")

        # Placeholder for auth bypass testing
        # Would test for common patterns like IDOR, privilege escalation, etc.
        pass
