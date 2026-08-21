"""Backward-compatible approval imports.

The project previously carried two incompatible gateways. The core gateway is
now the single implementation; this module exists only for old import paths.
"""

from ..core.approval_gateway import ApprovalGateway, ApprovalRequest, ApprovalStatus, RiskLevel

__all__ = ["ApprovalGateway", "ApprovalRequest", "ApprovalStatus", "RiskLevel"]
