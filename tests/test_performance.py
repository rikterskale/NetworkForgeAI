"""Performance smoke tests (TST-005): keep hot paths within time budgets.

These are generous wall-clock budgets meant to catch gross regressions (an
accidental O(n^2), a blocking call in an async path) rather than to measure
absolute performance. Run with the normal suite; they are CPU-only and need
no external services.
"""

import asyncio
import time

from networkforgeai.core.approval_gateway import ApprovalGateway, RiskLevel
from networkforgeai.integrations import summarize_findings
from networkforgeai.reporting import normalize_finding, to_json
from networkforgeai.reporting.generators import to_sarif


def _findings(count: int) -> list[dict[str, object]]:
    return [
        {
            "type": f"type-{i % 50}",
            "target": f"host-{i}.example.com",
            "title": f"Finding {i}",
            "severity": ("high", "medium", "low", "informational")[i % 4],
        }
        for i in range(count)
    ]


def test_summarize_findings_handles_large_volume():
    findings = _findings(20_000)
    start = time.perf_counter()
    summary = summarize_findings(findings)
    elapsed = time.perf_counter() - start
    assert summary["total"] == 20_000
    assert elapsed < 10.0, f"summarize_findings too slow: {elapsed:.2f}s"


def test_report_generation_scales_linearly():
    findings = _findings(5_000)
    start = time.perf_counter()
    to_json(findings)
    to_sarif(findings)
    elapsed = time.perf_counter() - start
    assert elapsed < 15.0, f"report generation too slow: {elapsed:.2f}s"


def test_normalize_finding_throughput():
    raw = _findings(2_000)
    start = time.perf_counter()
    for item in raw:
        normalize_finding(item)
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0, f"normalize_finding too slow: {elapsed:.2f}s"


def test_approval_gateway_concurrent_requests():
    async def scenario():
        gateway = ApprovalGateway(mode="manual")

        async def request(index: int):
            return await gateway.request_approval(
                agent_id=f"agent-{index}",
                action_type="port_scan",
                description="perf probe",
                target=f"host-{index}.example.com",
                risk_level=RiskLevel.LOW,
            )

        start = time.perf_counter()
        results = await asyncio.gather(*(request(i) for i in range(200)))
        elapsed = time.perf_counter() - start
        assert len(results) == 200
        assert all(r.status.value for r in results)
        assert elapsed < 5.0, f"approval requests too slow: {elapsed:.2f}s"

    asyncio.run(scenario())
