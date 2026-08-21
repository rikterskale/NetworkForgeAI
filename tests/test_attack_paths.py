"""Tests for attack-path auto-discovery (ADV-101)."""

from networkforgeai.core.attack_paths import AttackPathGraph, discover_attack_paths


def _findings():
    return [
        {"type": "open-port", "target": "web.example.com", "severity": "medium"},
        {"type": "default-credentials", "target": "web.example.com", "severity": "high"},
        {"type": "sudo-privesc", "target": "web.example.com", "severity": "critical"},
        {"type": "cors-misconfiguration", "target": "api.example.com", "severity": "low"},
    ]


def test_discovers_intra_host_chain():
    result = discover_attack_paths(_findings())
    paths = [tuple(p["stages"]) for p in result["paths"]]
    assert ("recon", "credential", "privilege") in paths
    # Sub-chains appear as suffixes of longer paths, not separate enumerations.
    assert any(p == ("recon", "credential", "privilege")[-2:] for p in [p[-2:] for p in paths])
    top = result["paths"][0]
    assert top["stages"] == ["recon", "credential", "privilege"]
    assert top["score"] >= max(p["score"] for p in result["paths"])


def test_entry_points_default_to_exposed_hosts():
    result = discover_attack_paths(_findings())
    assert result["entry_points"] == ["web.example.com"]
    # api.example.com only has a low-severity misconfig with no chain.
    assert all("api.example.com" not in n for p in result["paths"] for n in p["nodes"])


def test_explicit_targets_override_entry_points():
    findings = [
        {"type": "open-port", "target": "a.test", "severity": "high"},
        {"type": "default-credentials", "target": "a.test", "severity": "high"},
        {"type": "open-port", "target": "b.test", "severity": "low"},
        {"type": "default-credentials", "target": "b.test", "severity": "low"},
    ]
    result = discover_attack_paths(findings, targets=["b.test"])
    assert result["entry_points"] == ["b.test"]
    assert result["path_count"]
    assert all(n.startswith("b.test::") for p in result["paths"] for n in p["nodes"])


def test_lateral_movement_links_hosts():
    findings = [
        {"type": "default-credentials", "target": "a.test", "severity": "high"},
        {"type": "smb-relay", "target": "a.test", "severity": "high"},
        {"type": "open-port", "target": "b.test", "severity": "high"},
    ]
    edges = discover_attack_paths(findings)["graph"]["edges"]
    assert any(
        src.startswith("a.test::lateral") and dst.startswith("b.test::") for src, dst in edges
    )


def test_no_findings_yields_empty_graph():
    result = discover_attack_paths([])
    assert result["graph"]["nodes"] == []
    assert result["paths"] == [] and result["path_count"] == 0
    assert result["entry_points"] == []


def test_graph_simple_paths_never_revisit_nodes():
    graph = AttackPathGraph()
    graph.add_finding("a", "b", "high")
    graph.add_finding("b", "c", "high")
    graph.add_finding("c", "a", "critical")
    for path in graph.paths_from("a"):
        assert len(set(path)) == len(path)
