"""Base tool abstraction for offensive security tools."""

import logging
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ..core.approval_gateway import ApprovalGateway, ApprovalStatus, RiskLevel
from ..core.scope import ScopePolicy
from ..observability import command_digest, redact_text, safe_command_string
from ..sandbox.runner import SandboxRunner

logger = logging.getLogger(__name__)


class ToolRiskLevel(Enum):
    """Risk levels for tool operations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(Enum):
    """Categories of offensive security tools."""

    NETWORK_SCAN = "network_scan"
    WEB_SCAN = "web_scan"
    VULN_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PASSWORD_ATTACK = "password_attack"
    CLOUD = "cloud"
    WIRELESS = "wireless"
    SOCIAL_ENGINEERING = "social_engineering"
    FORENSICS = "forensics"
    REPORTING = "reporting"


@dataclass
class ToolResult:
    """Standardized result from tool execution."""

    tool_name: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    start_time: datetime
    end_time: datetime
    risk_level: ToolRiskLevel
    category: ToolCategory
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Calculate execution duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()

    @property
    def success(self) -> bool:
        """Check if tool executed successfully."""
        return self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "tool_name": self.tool_name,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration": self.duration,
            "risk_level": self.risk_level.value,
            "category": self.category.value,
            "findings": self.findings,
            "metadata": self.metadata,
            "success": self.success,
        }


class BaseTool(ABC):
    """Abstract base class for all offensive security tools."""

    name: str = "base_tool"
    description: str = "Base tool class"
    category: ToolCategory = ToolCategory.REPORTING
    risk_level: ToolRiskLevel = ToolRiskLevel.LOW
    requires_approval: bool = False

    def __init__(
        self,
        sandbox_mode: bool = True,
        dry_run: bool = False,
        approval_gateway: Optional[ApprovalGateway] = None,
        scope_policy: Optional[ScopePolicy] = None,
    ):
        """
        Initialize tool.

        Args:
            sandbox_mode: Run in isolated sandbox environment
            dry_run: Don't actually execute, just show what would run
        """
        self.sandbox_mode = sandbox_mode
        self.dry_run = dry_run
        self.approval_gateway = approval_gateway
        self.scope_policy = scope_policy
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

    @abstractmethod
    def build_command(self, target: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Build the command to execute the tool.

        Args:
            target: Target host/domain/URL
            options: Additional tool-specific options

        Returns:
            List of command arguments
        """
        pass

    def validate_target(self, target: str) -> bool:
        """
        Validate that target is within scope.

        Args:
            target: Target to validate

        Returns:
            True if target is valid and in scope
        """
        if not target or target.strip() == "":
            return False
        if self.scope_policy is not None and not self.scope_policy.contains(target):
            self.logger.warning("Target is outside the configured authorization scope: %s", target)
            return False
        return self.scope_policy is not None

    def _approval_required(self) -> bool:
        return self.requires_approval or self.risk_level in {
            ToolRiskLevel.HIGH,
            ToolRiskLevel.CRITICAL,
        }

    def execute(
        self, target: str, options: Optional[Dict[str, Any]] = None, timeout: int = 300
    ) -> ToolResult:
        """
        Execute the tool against a target.

        Args:
            target: Target host/domain/URL
            options: Additional tool-specific options
            timeout: Maximum execution time in seconds

        Returns:
            ToolResult with execution details and findings
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid or out-of-scope target: {target}")

        if self._approval_required() and not self.dry_run and self.approval_gateway is None:
            raise PermissionError(f"{self.name} requires an approval gateway")
        command = self.build_command(target, options)
        if self._approval_required() and not self.dry_run:
            request = self._run_approval_request(target, timeout, command_digest(command))
            if request.status != ApprovalStatus.APPROVED:
                raise PermissionError(
                    f"{self.name} execution was not approved: {request.status.value}"
                )

        return self._run_command(target, options, timeout)

    async def execute_async(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 300,
        *,
        approval_details: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """Async execution for use inside an event loop (e.g. agent orchestration).

        Approval is awaited through the shared gateway so the CLI/dashboard
        callbacks fire on the running loop, and the blocking subprocess is
        offloaded to a worker thread. This avoids the nested-event-loop
        limitation of the synchronous :meth:`execute` path.

        ``approval_details`` lets the caller enrich the human-facing approval
        request (e.g. the selected exploit module and a written justification)
        so an operator sees the full context before authorizing a high-risk
        action. It never relaxes the gate; it only adds context.
        """
        import asyncio

        if not self.validate_target(target):
            raise ValueError(f"Invalid or out-of-scope target: {target}")

        if self._approval_required() and not self.dry_run and self.approval_gateway is None:
            raise PermissionError(f"{self.name} requires an approval gateway")
        command = self.build_command(target, options)
        if self._approval_required() and not self.dry_run:
            gateway = self.approval_gateway
            assert gateway is not None
            details: Dict[str, Any] = {"command_builder": self.name}
            if approval_details:
                details.update(approval_details)
            request = await gateway.request_approval(
                agent_id=f"tool:{self.name}",
                action_type=self.name,
                description=f"Execute {self.name} against {target}",
                target=target,
                risk_level=RiskLevel(self.risk_level.value),
                details=details,
                timeout_seconds=timeout,
                command_digest=command_digest(command),
            )
            final = await gateway.wait_for_approval(request.id)
            if final.status != ApprovalStatus.APPROVED:
                raise PermissionError(
                    f"{self.name} execution was not approved: {final.status.value}"
                )

        return await asyncio.to_thread(self._run_command, target, options, timeout)

    def _run_command(
        self, target: str, options: Optional[Dict[str, Any]], timeout: int
    ) -> ToolResult:
        """Build the command and run it, returning a normalized ``ToolResult``.

        Callers are responsible for approval enforcement before invoking this.
        """
        command = self.build_command(target, options)
        command_str = safe_command_string(command)

        self.logger.info(f"Executing {self.name}: {command_str}")

        if self.dry_run:
            self.logger.info(f"[DRY RUN] Would execute: {command_str}")
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                exit_code=0,
                stdout="[DRY RUN] No execution performed",
                stderr="",
                start_time=datetime.now(),
                end_time=datetime.now(),
                risk_level=self.risk_level,
                category=self.category,
            )

        start_time = datetime.now()

        try:
            if self.sandbox_mode:
                result = SandboxRunner().run(command, timeout=timeout)
            else:
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=timeout, shell=False
                )

            end_time = datetime.now()

            tool_result = ToolResult(
                tool_name=self.name,
                command=command_str,
                exit_code=result.returncode,
                stdout=redact_text(result.stdout),
                stderr=redact_text(result.stderr),
                start_time=start_time,
                end_time=end_time,
                risk_level=self.risk_level,
                category=self.category,
                findings=[
                    self._sanitize_finding(finding)
                    for finding in self.parse_findings(result.stdout, result.stderr)
                ],
            )

            if result.returncode != 0:
                self.logger.warning(f"{self.name} exited with code {result.returncode}")
                if result.stderr:
                    self.logger.error("stderr: %s", redact_text(result.stderr))

            return tool_result

        except subprocess.TimeoutExpired:
            end_time = datetime.now()
            self.logger.error(f"{self.name} timed out after {timeout}s")
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                exit_code=-1,
                stdout="",
                stderr=f"Timeout after {timeout} seconds",
                start_time=start_time,
                end_time=end_time,
                risk_level=self.risk_level,
                category=self.category,
            )

        except Exception as e:
            end_time = datetime.now()
            self.logger.error(f"{self.name} failed: {str(e)}")
            return ToolResult(
                tool_name=self.name,
                command=command_str,
                exit_code=-1,
                stdout="",
                stderr=redact_text(str(e)),
                start_time=start_time,
                end_time=end_time,
                risk_level=self.risk_level,
                category=self.category,
            )

    def _run_approval_request(self, target: str, timeout: int, digest: str) -> Any:
        """Run the async approval protocol from this synchronous tool boundary."""
        import asyncio

        if self.approval_gateway is None:
            raise RuntimeError("Approval gateway is not configured for this tool")

        gateway = self.approval_gateway

        async def request_and_wait() -> Any:
            request = await gateway.request_approval(
                agent_id=f"tool:{self.name}",
                action_type=self.name,
                description=f"Execute {self.name} against {target}",
                target=target,
                risk_level=RiskLevel(self.risk_level.value),
                details={"command_builder": self.name},
                timeout_seconds=timeout,
                command_digest=digest,
            )
            return await gateway.wait_for_approval(request.id)

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(request_and_wait())
        raise RuntimeError(
            "Synchronous tool execution cannot request approval inside a running event loop"
        )

    def parse_findings(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse tool output to extract findings.

        Override this method in subclasses to implement custom parsing.

        Args:
            stdout: Standard output from tool
            stderr: Standard error from tool

        Returns:
            List of finding dictionaries
        """
        # Default implementation returns empty list
        # Subclasses should override with actual parsing logic
        return []

    @staticmethod
    def _sanitize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Prevent credentials and tokens from being emitted into reports."""
        secret_keys = {"password", "secret", "token", "api_key", "private_key"}
        sanitized = dict(finding)
        for key in secret_keys:
            if key in sanitized and sanitized[key] is not None:
                sanitized[key] = "[REDACTED]"
        return sanitized

    def get_info(self) -> Dict[str, Any]:
        """Get tool information."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "risk_level": self.risk_level.value,
            "requires_approval": self.requires_approval,
            "sandbox_mode": self.sandbox_mode,
            "dry_run": self.dry_run,
        }
