"""
Approval Gateway - Human-in-the-Loop Control System

All actions requiring exploitation, network access, or sensitive operations
must pass through this gateway for explicit human approval.
"""

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional

from ..observability import increment_metric, redact_mapping

logger = logging.getLogger(__name__)


def _as_utc(value: datetime) -> datetime:
    """Coerce legacy naive timestamps (pre-UTC migration state files) to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class RiskLevel(Enum):
    LOW = "low"  # Reconnaissance, passive scanning
    MEDIUM = "medium"  # Active scanning, non-destructive tests
    HIGH = "high"  # Exploitation attempts, authentication testing
    CRITICAL = "critical"  # Destructive tests, DoS, data modification


def action_requires_approval(
    risk_level: RiskLevel | str,
    category: str = "",
    *,
    passive: bool = False,
    dry_run: bool = False,
) -> bool:
    """Centralize approval requirements for executable actions."""
    if dry_run or passive:
        return False
    normalized_risk = (
        risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level).lower()
    )
    if normalized_risk in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
        return True
    return category in {
        "network_scan",
        "web_scan",
        "vulnerability_scan",
        "password_attack",
        "cloud",
        "post_exploitation",
        "exploitation",
        "wireless",
        "social_engineering",
    }


@dataclass
class ApprovalRequest:
    """Represents a request requiring human approval."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    action_type: str = ""
    description: str = ""
    target: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None
    command_digest: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "action_type": self.action_type,
            "description": self.description,
            "target": self.target,
            "risk_level": self.risk_level.value,
            "details": redact_mapping(self.details),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "approver_id": self.approver_id,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "rejection_reason": self.rejection_reason,
            "response_data": redact_mapping(self.response_data) if self.response_data else None,
            "command_digest": self.command_digest,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        return cls(
            id=data["id"],
            agent_id=data["agent_id"],
            action_type=data["action_type"],
            description=data["description"],
            target=data["target"],
            risk_level=RiskLevel(data["risk_level"]),
            details=data["details"],
            created_at=_as_utc(datetime.fromisoformat(data["created_at"])),
            expires_at=_as_utc(datetime.fromisoformat(data["expires_at"]))
            if data.get("expires_at")
            else None,
            status=ApprovalStatus(data["status"]),
            approver_id=data.get("approver_id"),
            approved_at=_as_utc(datetime.fromisoformat(data["approved_at"]))
            if data.get("approved_at")
            else None,
            rejection_reason=data.get("rejection_reason"),
            response_data=data.get("response_data"),
            command_digest=data.get("command_digest"),
        )


class ApprovalGateway:
    """
    Central gateway for managing human approval requests.

    All high-risk operations must request approval through this gateway
    before execution. Supports multiple approval modes:
    - Manual: Requires explicit human approval for each request
    - Auto-low: Auto-approve low-risk, manual for medium+
    - Auto-approved: Only for read-only reconnaissance (use with caution)
    """

    def __init__(
        self,
        mode: str = "manual",
        audit_log_path: Optional[str | Path] = None,
        *,
        audit_enabled: bool = True,
        block_destructive_actions: bool = False,
        require_justification_for_exploitation: bool = False,
    ):
        self.mode = mode
        self.requests: Dict[str, ApprovalRequest] = {}
        self.callbacks: Dict[str, Callable[[ApprovalRequest], Awaitable[None]]] = {}
        self._lock = asyncio.Lock()
        self.audit_log_path = Path(audit_log_path) if audit_log_path else None
        self.audit_enabled = audit_enabled
        self.block_destructive_actions = block_destructive_actions
        self.require_justification_for_exploitation = require_justification_for_exploitation
        self._emergency_stop = False
        self._emergency_stop_reason: Optional[str] = None

    async def request_approval(
        self,
        agent_id: str,
        action_type: str,
        description: str,
        target: str,
        risk_level: RiskLevel,
        details: Optional[Dict[str, Any]] = None,
        timeout_seconds: int = 300,
        command_digest: Optional[str] = None,
    ) -> ApprovalRequest:
        """
        Submit a request for human approval.

        Args:
            agent_id: ID of the requesting agent
            action_type: Type of action (e.g., "sql_injection_test", "exploit_attempt")
            description: Human-readable description of the action
            target: Target system/service
            risk_level: Risk classification
            details: Additional context for the approver
            timeout_seconds: Request expiration time

        Returns:
            ApprovalRequest object with status updated after approval/rejection
        """
        if self._emergency_stop:
            raise PermissionError(
                f"Emergency stop is active: {self._emergency_stop_reason or 'unspecified'}"
            )
        if isinstance(risk_level, str):
            risk_level = RiskLevel(risk_level.lower())
        request_details = details or {}
        if self.block_destructive_actions and request_details.get("destructive") is True:
            raise PermissionError("Destructive actions are blocked by runtime policy")
        if (
            self.require_justification_for_exploitation
            and risk_level is RiskLevel.CRITICAL
            and not str(request_details.get("justification") or "").strip()
        ):
            raise PermissionError("A written justification is required for critical actions")

        request = ApprovalRequest(
            agent_id=agent_id,
            action_type=action_type,
            description=description,
            target=target,
            risk_level=risk_level,
            details=request_details,
            command_digest=command_digest,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=timeout_seconds),
        )
        increment_metric("networkforgeai_approvals_requested_total")

        async with self._lock:
            self.requests[request.id] = request

        # Notify registered callbacks (e.g., UI updates)
        for callback in self.callbacks.values():
            try:
                await callback(request)
            except Exception:
                logger.exception("Approval callback failed")

        # Check auto-approval rules
        if self._should_auto_approve(risk_level):
            await self.approve(request.id, "auto_approved")

        return request

    def _should_auto_approve(self, risk_level: RiskLevel) -> bool:
        """Determine if request should be auto-approved based on mode and risk."""
        if self.mode == "manual":
            return False
        elif self.mode in {"auto-low", "moderate"}:
            return risk_level == RiskLevel.LOW
        elif self.mode in {"auto-approved", "lenient"}:
            return risk_level in {RiskLevel.LOW, RiskLevel.MEDIUM}
        return False

    async def approve(
        self, request_id: str, approver_id: str, response_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Approve a pending request."""
        async with self._lock:
            if request_id not in self.requests:
                return False

            request = self.requests[request_id]
            if request.status != ApprovalStatus.PENDING:
                return False

            request.status = ApprovalStatus.APPROVED
            request.approver_id = approver_id
            request.approved_at = datetime.now(timezone.utc)
            request.response_data = response_data

        self._audit(request)
        increment_metric("networkforgeai_approvals_approved_total")

        # Notify callbacks
        for callback in self.callbacks.values():
            try:
                await callback(request)
            except Exception:
                logger.exception("Approval callback failed")

        return True

    async def reject(self, request_id: str, approver_id: str, reason: str) -> bool:
        """Reject a pending request."""
        async with self._lock:
            if request_id not in self.requests:
                return False

            request = self.requests[request_id]
            if request.status != ApprovalStatus.PENDING:
                return False

            request.status = ApprovalStatus.REJECTED
            request.approver_id = approver_id
            request.rejection_reason = reason

        self._audit(request)
        increment_metric("networkforgeai_approvals_rejected_total")

        # Notify callbacks
        for callback in self.callbacks.values():
            try:
                await callback(request)
            except Exception:
                logger.exception("Approval callback failed")

        return True

    async def wait_for_approval(
        self, request_id: str, poll_interval: float = 1.0
    ) -> ApprovalRequest:
        """Wait asynchronously for a request to be approved or rejected."""
        while True:
            async with self._lock:
                if request_id not in self.requests:
                    raise ValueError(f"Request {request_id} not found")

                request = self.requests[request_id]

                if self._emergency_stop and request.status == ApprovalStatus.PENDING:
                    request.status = ApprovalStatus.CANCELLED
                    return request

                # Check expiration
                if request.expires_at and datetime.now(timezone.utc) > request.expires_at:
                    request.status = ApprovalStatus.EXPIRED
                    return request

                if request.status != ApprovalStatus.PENDING:
                    return request

            await asyncio.sleep(poll_interval)

    def register_callback(
        self, callback_id: str, callback: Callable[[ApprovalRequest], Awaitable[None]]
    ) -> None:
        """Register a callback to be notified of approval state changes."""
        self.callbacks[callback_id] = callback

    def unregister_callback(self, callback_id: str) -> None:
        """Remove a registered callback."""
        self.callbacks.pop(callback_id, None)

    def get_pending_requests(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return [r for r in self.requests.values() if r.status == ApprovalStatus.PENDING]

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get a specific request by ID."""
        return self.requests.get(request_id)

    def snapshot(self) -> list[dict[str, Any]]:
        """Serialize in-memory requests for crash recovery."""
        return [request.to_dict() for request in self.requests.values()]

    def restore(self, requests: list[dict[str, Any]]) -> None:
        """Restore persisted requests without re-emitting callbacks."""
        self.requests = {
            item["id"]: ApprovalRequest.from_dict(item)
            for item in requests
            if isinstance(item, dict) and item.get("id")
        }

    def clear_expired(self) -> None:
        """Remove expired requests from memory."""
        now = datetime.now(timezone.utc)
        expired = [
            rid for rid, req in self.requests.items() if req.expires_at and now > req.expires_at
        ]
        for rid in expired:
            del self.requests[rid]

    async def emergency_stop(self, reason: str = "operator requested stop") -> None:
        """Cancel pending approvals and block new actions until reset."""
        async with self._lock:
            self._emergency_stop = True
            self._emergency_stop_reason = reason
            pending = [
                request
                for request in self.requests.values()
                if request.status == ApprovalStatus.PENDING
            ]
            for request in pending:
                request.status = ApprovalStatus.CANCELLED
                self._audit(request)

    async def reset_emergency_stop(self) -> None:
        async with self._lock:
            self._emergency_stop = False
            self._emergency_stop_reason = None

    @property
    def emergency_stop_active(self) -> bool:
        return self._emergency_stop

    def _audit(self, request: ApprovalRequest) -> None:
        if not self.audit_enabled or not self.audit_log_path:
            return
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = request.to_dict()
        previous = ""
        if self.audit_log_path.exists():
            try:
                last = self.audit_log_path.read_text(encoding="utf-8").splitlines()[-1]
                previous = str(json.loads(last).get("audit_hash", ""))
            except (OSError, IndexError, json.JSONDecodeError):
                previous = ""
        payload["audit_previous_hash"] = previous
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload["audit_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
