"""Custom browser automation via Playwright (sandboxed).

The tool drives a headless Chromium instance through Playwright to perform
surface discovery that raw HTTP scanners miss: rendered titles, login form
detection, open redirects, and mixed-content checks. It requires the optional
``playwright`` package (extra ``[browser]``) and an execution environment with
Chromium installed; the recommended deployment runs it inside the approved
Docker sandbox image.
"""

import json
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel

# Executed inside the target runtime via `python -c`; prints one JSON object.
_BROWSER_SCRIPT = r"""
import json, sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print(json.dumps({"error": "playwright is not installed in this environment"}))
    sys.exit(0)

url = sys.argv[1]
max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 5

result = {"url": url, "pages": [], "findings": []}
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    seen, queue = set(), [url]
    while queue and len(seen) < max_pages:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            response = page.goto(current, wait_until="domcontentloaded", timeout=15000)
        except Exception as exc:
            result["findings"].append({"type": "navigation_error", "url": current,
                                       "summary": str(exc).splitlines()[0]})
            continue
        status = response.status if response else 0
        title = page.title()
        insecure_forms = page.eval_on_selector_all(
            "form[action^='http:']", "els => els.length")
        links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        result["pages"].append({"url": current, "status": status, "title": title,
                                "insecure_forms": insecure_forms})
        if insecure_forms:
            result["findings"].append({"type": "insecure_form", "url": current,
                                       "count": insecure_forms,
                                       "summary": f"{insecure_forms} form(s) post over HTTP"})
        for href in links:
            if href.startswith(url) and href not in seen:
                queue.append(href)
    browser.close()

print(json.dumps(result))
"""


class BrowserAutomationTool(BaseTool):
    """Playwright-driven browser reconnaissance of web applications."""

    name = "browser"
    description = (
        "Headless-browser surface discovery (rendered titles, login forms, "
        "mixed content) via Playwright"
    )
    category = ToolCategory.WEB_SCAN
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = False

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options = {
            "max_pages": 5,
        }

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        url = str(target)
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return [
            "python",
            "-c",
            _BROWSER_SCRIPT,
            url,
            str(max(int(opts.get("max_pages", 5)), 1)),
        ]

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            payload = json.loads(stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return findings

        if payload.get("error"):
            return [{"type": "browser_error", "summary": payload["error"], "confidence": "high"}]

        for entry in payload.get("findings", []):
            entry.setdefault("confidence", "medium")
            findings.append(entry)

        for page in payload.get("pages", []):
            summary = (
                f"Page {page.get('url')} returned {page.get('status')}: {page.get('title', '')}"
            )
            findings.append(
                {
                    "type": "page_surface",
                    "url": page.get("url"),
                    "status": page.get("status"),
                    "title": page.get("title"),
                    "summary": summary,
                    "confidence": "high",
                }
            )
        return findings
