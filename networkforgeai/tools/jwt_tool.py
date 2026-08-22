"""JWT security checks (TLS-105).

Passive token analysis: decodes a JWT without verification and reports
dangerous configurations (``alg: none``, header injection claims, missing or
excessive expiry). Pure Python; the probe script runs in the same execution
environment as the rest of the toolkit and prints one JSON object.
"""

import json
from typing import Any, Dict, List, Optional

from .base_tool import BaseTool, ToolCategory, ToolRiskLevel

_JWT_SCRIPT = r"""
import base64, json, sys

def b64url_decode(segment):
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)

token = sys.argv[1].strip()
try:
    head_b64, payload_b64, signature = token.split(".")
    header = json.loads(b64url_decode(head_b64))
    claims = json.loads(b64url_decode(payload_b64))
except Exception as exc:
    print(json.dumps({"error": f"not a decodable JWT: {exc}"}))
    sys.exit(0)

result = {"header": header, "claims": {k: v for k, v in claims.items()
           if k.lower() not in ("password", "secret", "token")}, "findings": []}

alg = str(header.get("alg", "")).lower()
if alg == "none":
    result["findings"].append({"type": "jwt_alg_none",
        "summary": "Token accepts/uses alg=none (unsigned)"})
if alg.startswith("hs") and any(k in header for k in ("jku", "x5u")):
    result["findings"].append({"type": "jwt_header_injection",
        "summary": f"Symmetric algorithm with attacker-influenced key header "
                   f"{[k for k in ('jku','x5u') if k in header]}"})
for key_field in ("jku", "x5u"):
    if key_field in header:
        result["findings"].append({"type": "jwt_key_header",
            "summary": f"Header carries {key_field} key reference: {header[key_field]}"})
kid = str(header.get("kid", ""))
if any(ch in kid for ch in ("'", '"', ";", "--", "(")):
    result["findings"].append({"type": "jwt_kid_injection",
        "summary": "kid value contains injection metacharacters"})
exp = claims.get("exp")
if exp is None:
    result["findings"].append({"type": "jwt_no_expiry",
        "summary": "Token has no exp claim"})
else:
    try:
        import datetime
        lifetime = float(exp) - datetime.datetime.now(datetime.timezone.utc).timestamp()
        if lifetime > 86400 * 7:
            result["findings"].append({"type": "jwt_long_lived",
                "summary": f"Token valid for over 7 days ({int(lifetime // 86400)} days)"})
    except (TypeError, ValueError):
        pass
print(json.dumps(result))
"""


class JwtAnalyzerTool(BaseTool):
    """Analyze JWTs for common misconfigurations (no cryptographic verification)."""

    name = "jwt-analyzer"
    description = (
        "Decode JWTs and flag alg=none, key-header injection, kid injection, and expiry problems"
    )
    category = ToolCategory.WEB_SCAN
    risk_level = ToolRiskLevel.LOW
    requires_approval = False
    passive = True

    def __init__(self, sandbox_mode: bool = True, dry_run: bool = False):
        super().__init__(sandbox_mode=sandbox_mode, dry_run=dry_run)
        self.default_options: Dict[str, Any] = {}

    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        opts = {**self.default_options, **(options or {})}
        token = str(opts.get("token") or target).strip()
        if not token or token.count(".") != 2:
            raise ValueError("jwt-analyzer requires a JWT with three dot-separated segments")
        return ["python", "-c", _JWT_SCRIPT, token]

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            payload = json.loads(stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return [{"type": "jwt_parse_error", "summary": stdout[:200], "confidence": "high"}]
        if payload.get("error"):
            return [{"type": "jwt_invalid", "summary": payload["error"], "confidence": "high"}]
        for item in payload.get("findings", []):
            item.setdefault("confidence", "high")
            item.setdefault("severity", "high" if "none" in item["type"] else "medium")
            findings.append(item)
        if not findings:
            findings.append(
                {
                    "type": "jwt_no_issues",
                    "summary": "No high-risk JWT configuration detected",
                    "confidence": "medium",
                    "severity": "informational",
                }
            )
        return findings
