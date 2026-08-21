"""
Approval Gateway - Human-in-the-Loop Control System

This module implements the critical safety layer requiring explicit human approval
for all offensive security actions. No exploitation or validation occurs without approval.
"""

import asyncio
import json
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
import structlog

logger = structlog.get_logger()


class ActionType(str, Enum):
    """Types of actions requiring approval."""
    RECON_PASSIVE = "recon_passive"  # Passive reconnaissance (usually auto-approved)
    RECON_ACTIVE = "recon_active"  # Active scanning
    VULNERABILITY_VALIDATION = "vulnerability_validation"  # Active validation tests
    EXPLOITATION_ATTEMPT = "exploitation_attempt"  # Exploit execution
    POST_EXPLOITATION = "post_exploitation"  # Post-exploitation activities
    DATA_EXFILTRATION = "data_exfiltration"  # Data collection (simulated)
    LATERAL_MOVEMENT = "lateral_movement"  # Moving to other systems
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Escalating privileges


class ApprovalStatus(str, Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass
class ApprovalRequest:
    """Represents a request for human approval."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType = ActionType.RECON_PASSIVE
    target: str = ""
    description: str = ""
    risk_level: str = "low"  # low, medium, high, critical
    justification_required: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    
    # Action details
    command: Optional[str] = None  # The actual command/tool to execute
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_outcome: str = ""
    
    # Approval metadata
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    operator_justification: Optional[str] = None
    
    # Context
    scan_id: str = ""
    agent_id: str = ""
    parent_finding_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat() if self.expires_at else None
        data['approved_at'] = self.approved_at.isoformat() if self.approved_at else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ApprovalRequest':
        """Create from dictionary."""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        if data.get('approved_at'):
            data['approved_at'] = datetime.fromisoformat(data['approved_at'])
        data['status'] = ApprovalStatus(data['status'])
        data['action_type'] = ActionType(data['action_type'])
        return cls(**data)


class ApprovalGateway:
    """
    Central approval gateway enforcing human-in-the-loop control.
    
    All offensive actions must pass through this gateway before execution.
    Supports multiple approval interfaces: CLI, GUI dashboard, and API.
    """
    
    def __init__(self, approval_dir: Path, audit_log_path: Optional[Path] = None):
        self.approval_dir = approval_dir
        self.audit_log_path = audit_log_path or (approval_dir / "audit.log")
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.approval_callbacks: Dict[str, Callable] = {}
        self._lock = asyncio.Lock()
        
        # Ensure directories exist
        self.approval_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(
            "ApprovalGateway initialized",
            approval_dir=str(approval_dir),
            audit_log=str(self.audit_log_path)
        )
    
    async def request_approval(self, request: ApprovalRequest) -> str:
        """
        Submit an approval request and wait for decision.
        
        Returns the request ID for tracking.
        Blocks until approval is granted, rejected, or expired.
        """
        async with self._lock:
            self.pending_requests[request.id] = request
            self._persist_request(request)
        
        logger.info(
            "Approval requested",
            request_id=request.id,
            action_type=request.action_type.value,
            target=request.target,
            risk_level=request.risk_level
        )
        
        # Notify registered callbacks (e.g., dashboard UI)
        await self._notify_callbacks(request)
        
        # Wait for decision
        return await self._wait_for_decision(request)
    
    async def _wait_for_decision(self, request: ApprovalRequest) -> str:
        """Wait for approval decision with timeout."""
        while True:
            # Check if expired
            if request.expires_at and datetime.utcnow() > request.expires_at:
                request.status = ApprovalStatus.EXPIRED
                self._persist_request(request)
                logger.warning("Approval request expired", request_id=request.id)
                return request.id
            
            # Reload from disk to check for updates
            await asyncio.sleep(0.5)  # Poll interval
            updated_request = self._load_request(request.id)
            if updated_request:
                request = updated_request
            
            if request.status != ApprovalStatus.PENDING:
                break
        
        async with self._lock:
            if request.id in self.pending_requests:
                del self.pending_requests[request.id]
        
        # Log the decision
        self._log_audit_event(request)
        
        return request.id
    
    async def approve(
        self,
        request_id: str,
        operator_id: str = "anonymous",
        justification: Optional[str] = None
    ) -> bool:
        """Approve a pending request."""
        async with self._lock:
            request = self.pending_requests.get(request_id)
            if not request:
                request = self._load_request(request_id)
            
            if not request or request.status != ApprovalStatus.PENDING:
                logger.warning("Cannot approve", request_id=request_id, reason="invalid state")
                return False
            
            request.status = ApprovalStatus.APPROVED
            request.approved_by = operator_id
            request.approved_at = datetime.utcnow()
            request.operator_justification = justification
            
            self._persist_request(request)
        
        logger.info(
            "Approval granted",
            request_id=request_id,
            operator=operator_id,
            justification=justification
        )
        
        self._log_audit_event(request)
        return True
    
    async def reject(
        self,
        request_id: str,
        operator_id: str = "anonymous",
        reason: Optional[str] = None
    ) -> bool:
        """Reject a pending request."""
        async with self._lock:
            request = self.pending_requests.get(request_id)
            if not request:
                request = self._load_request(request_id)
            
            if not request or request.status != ApprovalStatus.PENDING:
                logger.warning("Cannot reject", request_id=request_id, reason="invalid state")
                return False
            
            request.status = ApprovalStatus.REJECTED
            request.approved_by = operator_id
            request.approved_at = datetime.utcnow()
            request.rejection_reason = reason
            
            self._persist_request(request)
        
        logger.info(
            "Approval rejected",
            request_id=request_id,
            operator=operator_id,
            reason=reason
        )
        
        self._log_audit_event(request)
        return True
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending approval requests."""
        return [r for r in self.pending_requests.values() if r.status == ApprovalStatus.PENDING]
    
    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get a specific approval request."""
        return self.pending_requests.get(request_id) or self._load_request(request_id)
    
    def register_callback(self, callback: Callable) -> None:
        """Register a callback for new approval requests."""
        self.approval_callbacks[id(callback)] = callback
    
    def unregister_callback(self, callback: Callable) -> None:
        """Unregister a callback."""
        self.approval_callbacks.pop(id(callback), None)
    
    async def _notify_callbacks(self, request: ApprovalRequest) -> None:
        """Notify all registered callbacks of new request."""
        for callback in self.approval_callbacks.values():
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(request)
                else:
                    callback(request)
            except Exception as e:
                logger.error("Callback error", error=str(e))
    
    def _persist_request(self, request: ApprovalRequest) -> None:
        """Persist request to disk."""
        filepath = self.approval_dir / f"{request.id}.json"
        with open(filepath, 'w') as f:
            json.dump(request.to_dict(), f, indent=2)
    
    def _load_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Load request from disk."""
        filepath = self.approval_dir / f"{request_id}.json"
        if not filepath.exists():
            return None
        with open(filepath, 'r') as f:
            data = json.load(f)
        return ApprovalRequest.from_dict(data)
    
    def _log_audit_event(self, request: ApprovalRequest) -> None:
        """Log approval decision to audit trail."""
        if not self.audit_log_path.parent.exists():
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.id,
            "action_type": request.action_type.value,
            "target": request.target,
            "risk_level": request.risk_level,
            "status": request.status.value,
            "approved_by": request.approved_by,
            "justification": request.operator_justification,
            "rejection_reason": request.rejection_reason,
            "scan_id": request.scan_id,
            "agent_id": request.agent_id
        }
        
        with open(self.audit_log_path, 'a') as f:
            f.write(json.dumps(audit_entry) + "\n")


# Global approval gateway instance (initialized by orchestrator)
_gateway: Optional[ApprovalGateway] = None


def get_approval_gateway() -> ApprovalGateway:
    """Get the global approval gateway instance."""
    if _gateway is None:
        raise RuntimeError("ApprovalGateway not initialized. Call initialize_gateway first.")
    return _gateway


def initialize_gateway(approval_dir: Path) -> ApprovalGateway:
    """Initialize the global approval gateway."""
    global _gateway
    _gateway = ApprovalGateway(approval_dir)
    return _gateway
