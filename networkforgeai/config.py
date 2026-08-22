"""
Configuration management for NetworkForgeAI.

Loads settings from environment variables with validation for safety-critical settings.
"""

from enum import Enum
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ApprovalMode(str, Enum):
    """Approval strictness levels."""

    STRICT = "strict"  # All actions require explicit approval
    MODERATE = "moderate"  # Recon auto-approved, others require approval
    LENIENT = "lenient"  # Recon/validation auto-approved, exploitation requires approval


class ReportFormat(str, Enum):
    """Supported report output formats."""

    MARKDOWN = "markdown"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"
    PDF = "pdf"
    HTML = "html"


class Settings(BaseSettings):
    """Application configuration with safety-first defaults."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # LLM Configuration
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API key")
    anthropic_api_key: Optional[str] = Field(default=None, description="Anthropic API key")
    google_api_key: Optional[str] = Field(default=None, description="Google API key")
    litellm_model: str = Field(default="openai/gpt-4", description="Model to use via LiteLLM")
    local_llm_url: Optional[str] = Field(default=None, description="Local LLM endpoint URL")

    # Target Scope - CRITICAL SAFETY SETTING
    target_scope: str = Field(
        default="",
        description="Comma-separated list of authorized targets (domains, IPs, CIDR ranges)",
    )

    @field_validator("target_scope")
    @classmethod
    def validate_target_scope(cls, v: str) -> str:
        """Warn if target scope is empty (will require runtime definition)."""
        if not v or not v.strip():
            # Don't block, but this will require interactive scope definition
            pass
        return v.strip()

    # Approval System - CRITICAL SAFETY SETTING
    approval_mode: ApprovalMode = Field(
        default=ApprovalMode.STRICT, description="Approval strictness level"
    )

    block_destructive_actions: bool = Field(
        default=True, description="Block potentially destructive actions regardless of approval"
    )

    require_justification_for_exploitation: bool = Field(
        default=True, description="Require written justification before exploitation attempts"
    )

    audit_all_approvals: bool = Field(
        default=True, description="Log all approval decisions for audit trail"
    )

    # Dashboard Configuration
    dashboard_port: int = Field(default=8080, ge=1, le=65535)
    dashboard_auth_token: str = Field(
        default="", description="Required bearer token for dashboard access"
    )

    # Caido Proxy
    caido_web_port: int = Field(default=8090, ge=1, le=65535)
    caido_proxy_port: int = Field(default=8091, ge=1, le=65535)
    caido_license: Optional[str] = Field(default=None)

    # Reporting
    report_formats: List[ReportFormat] = Field(
        default=[ReportFormat.MARKDOWN, ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF],
        description="Output formats for reports",
    )
    report_output_dir: str = Field(default="./reports")

    # Session Management
    session_timeout_minutes: int = Field(default=60, ge=5, le=1440)
    max_concurrent_agents: int = Field(default=5, ge=1, le=20)

    # CI/CD Mode
    ci_mode: bool = Field(default=False, description="Run in CI/CD pipeline mode")

    # Logging
    log_level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    log_format: str = Field(default="text", pattern="^(text|json)$")

    @property
    def parsed_target_scope(self) -> List[str]:
        """Parse target scope into list of targets."""
        if not self.target_scope:
            return []
        return [t.strip() for t in self.target_scope.split(",") if t.strip()]

    def resolve_scope(self, cli_scope: list[str] | None) -> list[str]:
        """Resolve one-run CLI scope over the persistent environment scope."""
        return list(cli_scope) if cli_scope else self.parsed_target_scope

    def resolve_output_dir(self, cli_output_dir: str | None) -> str:
        """Resolve a one-run output directory over the configured directory."""
        return cli_output_dir or self.report_output_dir

    def resolve_approval_mode(self, cli_mode: str | None) -> str:
        """Resolve a one-run approval mode over the configured mode."""
        return cli_mode or self.approval_mode.value

    @property
    def is_strict_mode(self) -> bool:
        """Check if running in strict approval mode."""
        return self.approval_mode == ApprovalMode.STRICT

    def validate_llm_config(self) -> bool:
        """Validate that at least one LLM provider is configured."""
        has_provider = any(
            [self.openai_api_key, self.anthropic_api_key, self.google_api_key, self.local_llm_url]
        )
        if not has_provider:
            raise ValueError(
                "No LLM provider configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, "
                "GOOGLE_API_KEY, or LOCAL_LLM_URL in your .env file."
            )
        return True

    #: Substrings that mark an unedited placeholder dashboard token.
    _PLACEHOLDER_TOKEN_MARKERS = ("change", "your_", "replace", "example", "placeholder")

    def validate_security_config(self) -> bool:
        """Reject unsafe production defaults before starting a scan.

        An empty token is allowed (the dashboard then denies all requests, which
        is fail-closed); a non-empty token that still looks like a shipped
        placeholder is rejected so it cannot be deployed by accident.
        """
        if not self.parsed_target_scope:
            raise ValueError("TARGET_SCOPE must contain at least one authorized target")
        token = self.dashboard_auth_token.strip()
        if token and any(marker in token.lower() for marker in self._PLACEHOLDER_TOKEN_MARKERS):
            raise ValueError(
                "DASHBOARD_AUTH_TOKEN must be changed from the development placeholder"
            )
        return True

    def diagnostics(self) -> list[dict[str, object]]:
        """Return safe, structured diagnostics without exposing secret values."""
        token = self.dashboard_auth_token.strip()
        report_dir = Path(self.report_output_dir).expanduser()
        return [
            {
                "name": "target_scope",
                "ok": bool(self.parsed_target_scope),
                "detail": f"{len(self.parsed_target_scope)} authorized scope "
                f"{'entry' if len(self.parsed_target_scope) == 1 else 'entries'}",
            },
            {
                "name": "approval_mode",
                "ok": self.is_strict_mode,
                "detail": self.approval_mode.value,
            },
            {
                "name": "destructive_actions_blocked",
                "ok": self.block_destructive_actions,
                "detail": str(self.block_destructive_actions).lower(),
            },
            {
                "name": "exploitation_justification",
                "ok": self.require_justification_for_exploitation,
                "detail": str(self.require_justification_for_exploitation).lower(),
            },
            {
                "name": "dashboard_token",
                "ok": bool(token)
                and not any(marker in token.lower() for marker in self._PLACEHOLDER_TOKEN_MARKERS),
                "detail": "configured" if token else "missing (protected routes deny access)",
            },
            {
                "name": "report_output_directory",
                "ok": report_dir.exists() and report_dir.is_dir() or report_dir.parent.exists(),
                "detail": str(report_dir),
            },
            {
                "name": "llm_provider",
                "ok": True,
                "required": False,
                "detail": "configured"
                if (
                    self.openai_api_key
                    or self.anthropic_api_key
                    or self.google_api_key
                    or self.local_llm_url
                )
                else "optional provider not configured",
            },
            {"name": "logging", "ok": True, "detail": f"{self.log_level}/{self.log_format}"},
        ]


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings
