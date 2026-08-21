"""SIEM alert forwarding (INT-201) and finding correlation (INT-202).

Splunk HEC forwarder posts sanitized, CEF-encoded or JSON events over the
shared HTTPS-only transport. Correlation helpers group normalized findings
across sources so duplicate observations from different tools collapse into
single records keyed by target and weakness.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from ..reporting.models import prepare_findings
from .notifications import HttpsJsonClient

__all__ = ["cef_encode", "SplunkHecForwarder", "correlate_findings"]


_CEF_ESCAPES = {"\\": "\\\\", "=": "\\=", "|": "\\|", "\n": "\\n", "\r": "\\r"}


def _cef_field(value: Any) -> str:
    return "".join(_CEF_ESCAPES.get(ch, ch) for ch in str(value or ""))


def cef_encode(finding: dict[str, Any]) -> str:
    """Render one normalized finding as a single-line CEF event."""
    row = prepare_findings([finding])[0]
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 3}
    severity = str(row.get("severity", "informational"))
    cef_severity = severity_map.get(severity, 0)
    signature = f"NetworkForgeAI {row.get('type', 'unknown')}"
    extension = " ".join(
        f"{key}={_cef_field(row.get(key))}"
        for key in ("target", "type", "title", "severity", "remediation")
    )
    return f"CEF:0|NetworkForgeAI|scanner|1.0|100|{signature}|{cef_severity}|{extension}"


class SplunkHecForwarder:
    """Forward findings to a Splunk HTTP Event Collector over HTTPS (INT-201)."""

    def __init__(
        self,
        hec_url: str,
        token: str,
        index: str | None = None,
        source_type: str = "networkforgeai:finding",
        use_cef: bool = False,
        timeout: float = 10.0,
    ):
        if not token or token.strip() == "":
            raise ValueError("A non-empty Splunk HEC token is required")
        if not hec_url.startswith("https://"):
            raise ValueError("Splunk HEC URL must use HTTPS")
        self.index = index
        self.source_type = source_type
        self.use_cef = use_cef
        self.client = HttpsJsonClient(
            hec_url,
            headers={"Authorization": f"Splunk {token}"},
            timeout=timeout,
        )

    def forward_finding(self, finding: dict[str, Any]) -> int:
        """Send one finding as a single HEC event."""
        event: str | dict[str, Any]
        if self.use_cef:
            event = cef_encode(finding)
        else:
            event = prepare_findings([finding])[0]
        payload: dict[str, Any] = {
            "sourcetype": self.source_type,
            "event": event,
        }
        if self.index:
            payload["index"] = self.index
        return self.client.post(payload)

    def forward_findings(self, findings: list[dict[str, Any]]) -> list[int]:
        return [self.forward_finding(finding) for finding in prepare_findings(findings)]


def correlate_findings(
    source_groups: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Merge findings from multiple scanner sources (INT-202).

    ``source_groups`` maps a source label (e.g. ``"nmap"``, ``"zap"``) to raw
    findings. Findings are normalized, then grouped by (target, weakness key)
    where the weakness key is the CWE when known, else the finding type. Each
    group becomes one correlated record listing the observing sources; the
    highest severity wins.

    Returns records shaped as::

        {"correlation_id", "target", "weakness", "severity",
         "sources": [..], "titles": [..]}
    """
    groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "sources": set(),
            "titles": set(),
            "severity_rank": -1,
            "severity": "informational",
        }
    )
    order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for source, findings in source_groups.items():
        for row in prepare_findings(findings):
            weakness = str(row.get("cwe") or row.get("type") or "unknown")
            key = (str(row.get("target", "")), weakness)
            entry = groups[key]
            entry["sources"].add(source)
            entry["titles"].add(str(row.get("title") or row.get("type") or weakness))
            rank = order.get(str(row.get("severity", "informational")), 0)
            if rank > entry["severity_rank"]:
                entry["severity_rank"] = rank
                entry["severity"] = str(row.get("severity", "informational"))
    records: list[dict[str, Any]] = []
    for (target, weakness), entry in groups.items():
        correlation_id = hashlib.sha256(f"{target}|{weakness}".encode()).hexdigest()[:12]
        records.append(
            {
                "correlation_id": correlation_id,
                "target": target,
                "weakness": weakness,
                "severity": entry["severity"],
                "sources": sorted(entry["sources"]),
                "titles": sorted(entry["titles"]),
            }
        )
    records.sort(key=lambda r: r["correlation_id"])
    return records
