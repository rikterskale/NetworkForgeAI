"""
NetworkForgeAI Agents Package

Specialized AI agents for different phases of penetration testing.
All agents require human approval before executing high-risk operations.
"""

__version__ = "0.1.0"
from .recon_agent import ReconAgent
from .specialized import (
    APISecurityAgent,
    NetworkExploitationAgent,
    PlanningAgent,
    PostExploitationAgent,
    QualityAssuranceAgent,
    ReportingAgent,
    WebApplicationAgent,
)
from .vuln_scanner_agent import VulnerabilityScannerAgent

__all__ = [
    "ReconAgent",
    "VulnerabilityScannerAgent",
    "PlanningAgent",
    "ReportingAgent",
    "QualityAssuranceAgent",
    "WebApplicationAgent",
    "APISecurityAgent",
    "NetworkExploitationAgent",
    "PostExploitationAgent",
]
