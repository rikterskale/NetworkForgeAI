"""Attack-path auto-discovery (ADV-101).

Builds a directed attack graph over normalized findings and discovered
assets, then enumerates simple paths from entry points to high-value
targets. Pure computation over shared-context data; every path it proposes
remains advisory and subject to the approval workflow.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..reporting.models import prepare_findings

__all__ = ["AttackPathGraph", "discover_attack_paths"]

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Edge weights: how finding classes typically chain during an assessment.
_CHAIN_HINTS: tuple[tuple[str, str], ...] = (
    ("recon", "credential"),
    ("recon", "exposure"),
    ("exposure", "injection"),
    ("exposure", "misconfiguration"),
    ("credential", "privilege"),
    ("credential", "lateral"),
    ("misconfiguration", "privilege"),
    ("injection", "privilege"),
    ("injection", "lateral"),
)


def _stage_of(finding_type: str) -> str:
    lowered = finding_type.lower()
    for keyword, stage in (
        ("port", "recon"),
        ("service", "recon"),
        ("directory", "recon"),
        ("subdomain", "recon"),
        ("default-cred", "credential"),
        ("password", "credential"),
        ("jwt", "credential"),
        ("session", "credential"),
        ("s3", "exposure"),
        ("bucket", "exposure"),
        ("dashboard", "exposure"),
        ("listing", "exposure"),
        ("sqli", "injection"),
        ("xss", "injection"),
        ("rce", "injection"),
        ("header", "misconfiguration"),
        ("tls", "misconfiguration"),
        ("cors", "misconfiguration"),
        ("privesc", "privilege"),
        ("sudo", "privilege"),
        ("lateral", "lateral"),
        ("smb", "lateral"),
    ):
        if keyword in lowered:
            return stage
    return "exposure"


class AttackPathGraph:
    """Directed graph of hosts linked by chained weakness stages."""

    def __init__(self) -> None:
        self._adjacency: dict[str, set[str]] = defaultdict(set)
        self._node_severity: dict[str, int] = defaultdict(int)

    def add_finding(self, source: str, target: str, severity: str) -> None:
        self._adjacency[source].add(target)
        self._adjacency.setdefault(target, set())
        rank = _SEVERITY_RANK.get(severity, 0)
        self._node_severity[source] = max(self._node_severity[source], rank)
        self._node_severity[target] = max(self._node_severity[target], rank)

    def nodes(self) -> list[str]:
        return sorted(self._adjacency)

    def edges(self) -> list[tuple[str, str]]:
        return [(a, b) for a in sorted(self._adjacency) for b in sorted(self._adjacency[a])]

    def paths_from(self, start: str, min_target_severity: int = 2) -> list[list[str]]:
        """Enumerate simple paths from ``start`` to sufficiently severe hosts."""
        results: list[list[str]] = []
        visited: set[str] = set()

        def walk(path: list[str]) -> None:
            current = path[-1]
            if len(path) > 1 and self._node_severity.get(current, 0) >= min_target_severity:
                results.append(list(path))
            for nxt in sorted(self._adjacency.get(current, ())):
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    walk(path)
                    path.pop()
                    visited.discard(nxt)

        visited.add(start)
        walk([start])
        return results


def discover_attack_paths(
    findings: list[dict[str, Any]],
    targets: list[str] | None = None,
) -> dict[str, Any]:
    """Build an attack graph from findings and enumerate candidate paths.

    ``targets`` optionally supplies known entry points (e.g. the scan scope).
    When omitted, all hosts with at least one recon/exposure-class finding are
    treated as entry points. Returns graph edges plus scored simple paths.
    """
    rows = prepare_findings(findings)
    host_stage: dict[tuple[str, str], int] = {}
    graph = AttackPathGraph()

    # Group per-host weaknesses into ordered stages.
    by_host: dict[str, dict[str, int]] = defaultdict(dict)
    for row in rows:
        target = str(row.get("target", ""))
        stage = _stage_of(str(row.get("type", "")))
        rank = _SEVERITY_RANK.get(str(row.get("severity", "informational")), 0)
        by_host[target][stage] = max(by_host[target].get(stage, 0), rank)
        host_stage[(target, stage)] = rank

    # Intra-host chaining by stage order.
    stage_order: list[str] = []
    for earlier, later in _CHAIN_HINTS:
        for stage in (earlier, later):
            if stage not in stage_order:
                stage_order.append(stage)
    for host, stages in sorted(by_host.items()):
        present = [s for s in stage_order if s in stages]
        for earlier, later in zip(present, present[1:]):
            if (earlier, later) in _CHAIN_HINTS:
                graph.add_finding(f"{host}::{earlier}", f"{host}::{later}", "medium")

    # Inter-host chaining via lateral movement when multiple hosts exist.
    hosts = sorted(by_host)
    for host in hosts:
        if any(k in by_host[host] for k in ("lateral", "credential")):
            for other in hosts:
                if other != host and "recon" in by_host[other]:
                    graph.add_finding(f"{host}::lateral", f"{other}::recon", "medium")

    entry_points = targets or [
        host for host, stages in by_host.items() if "recon" in stages or "exposure" in stages
    ]

    paths: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for entry in sorted(entry_points):
        start_candidates = [
            f"{entry}::{stage}"
            for stage in ("recon", "exposure")
            if f"{entry}::{stage}" in graph.nodes()
        ]
        for start in start_candidates:
            for path in graph.paths_from(start):
                key = tuple(path)
                if key not in seen:
                    seen.add(key)
                    stages = [node.rsplit("::", 1)[-1] for node in path]
                    score = len(path) * 2 + max(
                        (
                            _SEVERITY_RANK.get(
                                by_host.get(node.split("::")[0], {}).get(stage, "informational"), 0
                            )
                            for node, stage in zip(path, stages)
                        ),
                        default=0,
                    )
                    paths.append({"nodes": path, "score": score, "stages": stages})

    paths.sort(key=lambda p: (-p["score"], p["nodes"]))
    return {
        "graph": {
            "nodes": graph.nodes(),
            "edges": [list(edge) for edge in graph.edges()],
        },
        "entry_points": sorted(entry_points),
        "paths": paths[:20],
        "path_count": len(paths),
    }
