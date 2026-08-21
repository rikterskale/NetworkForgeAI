"""GraphQL security checks (TLS-106).

Probes a GraphQL endpoint for common misconfigurations: introspection enabled,
developer IDEs (GraphiQL/Playground) exposed, query batching accepted, and
verbose error leakage. Uses only the standard library inside the probe script.
"""

import json
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel

_GRAPHQL_SCRIPT = r"""
import json, sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError

endpoint = sys.argv[1]
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0

def post(body):
    req = Request(endpoint, data=json.dumps(body).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")

result = {"endpoint": endpoint, "findings": []}

# Introspection
status, body = post({"query": "{ __schema { types { name } } }"})
try:
    data = json.loads(body)
except ValueError:
    data = {}
if "errors" not in data and "__schema" in body:
    result["findings"].append({"type": "introspection_enabled",
        "summary": "Schema introspection is enabled"})
elif status == 200:
    result["findings"].append({"type": "introspection_disabled",
        "summary": "Introspection rejected", "confidence": "medium"})

# Developer IDE exposure
for path in ("graphiql", "playground"):
    probe = endpoint.rstrip("/") + "/" + path
    try:
        with urlopen(probe, timeout=timeout) as resp:
            text = resp.read(4096).decode("utf-8", "replace")
            if "graphiql" in text.lower() or "playground" in text.lower():
                result["findings"].append({"type": "ide_exposed",
                    "summary": f"Developer IDE exposed at {probe}"})
    except Exception:
        pass

# Query batching (array of operations accepted)
status, body = post([
    {"query": "query { __typename }"},
    {"query": "query { __typename }"},
])
if status == 200 and "errors" not in body.lower():
    result["findings"].append({"type": "batching_accepted",
        "summary": "Endpoint accepts operation arrays (batching/brute-force risk)"})

# Error verbosity
status, body = post({"query": "{ nonExistentFieldVeryUnlikely }"})
if "nonExistentFieldVeryUnlikely" in body and ("Cannot query" in body or "message" in body):
    result["findings"].append({"type": "verbose_errors",
        "summary": "Errors echo full query context (stack traces / field hints possible)"})

print(json.dumps(result))
"""


class GraphQLProbeTool(BaseTool):
    """Probe GraphQL endpoints for misconfigurations."""

    name = "graphql-probe"
    description = (
        "Check GraphQL endpoints for introspection exposure, developer IDEs, "
        "batching acceptance, and verbose errors"
    )
    category = ToolCategory.WEB_SCAN
    risk_level = ToolRiskLevel.MEDIUM
    requires_approval = False

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options: Dict[str, Any] = {"timeout": 10}

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        url = str(target)
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return ["python", "-c", _GRAPHQL_SCRIPT, url, str(int(opts.get("timeout", 10)))]

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        try:
            payload = json.loads(stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return [{"type": "graphql_probe_error", "summary": stdout[:200], "confidence": "low"}]
        findings: List[Dict[str, Any]] = []
        for item in payload.get("findings", []):
            item.setdefault("confidence", "high")
            if item["type"] in {"introspection_enabled", "ide_exposed"}:
                item.setdefault("severity", "medium")
            else:
                item.setdefault("severity", "low")
            findings.append(item)
        if not findings:
            findings.append(
                {
                    "type": "graphql_no_issues",
                    "summary": "No GraphQL misconfigurations detected by the probes",
                    "confidence": "medium",
                    "severity": "informational",
                }
            )
        return findings
