"""Offensive security tools integration package."""

from typing import Any, cast

from .base_tool import BaseTool, ToolCategory, ToolResult, ToolRiskLevel
from .browser_tool import BrowserAutomationTool
from .metasploit_tool import MetasploitTool
from .nmap_tool import MasscanTool, NmapTool
from .password_tools import CrackMapExecTool, HydraTool, ImpacketTools
from .web_scanner_tools import NiktoTool, OWASPZAPTool, SQLMapTool

__all__ = [
    # Base classes
    "BaseTool",
    "ToolResult",
    "ToolCategory",
    "ToolRiskLevel",
    # Network scanning tools
    "NmapTool",
    "MasscanTool",
    # Web application tools
    "NiktoTool",
    "OWASPZAPTool",
    "SQLMapTool",
    # Password/credential tools
    "HydraTool",
    "CrackMapExecTool",
    "ImpacketTools",
    "MetasploitTool",
    "BrowserAutomationTool",
]


def get_available_tools() -> dict[str, type[BaseTool]]:
    """Get dictionary of all available tools."""
    return {
        "nmap": NmapTool,
        "masscan": MasscanTool,
        "nikto": NiktoTool,
        "owasp-zap": OWASPZAPTool,
        "sqlmap": SQLMapTool,
        "hydra": HydraTool,
        "crackmapexec": CrackMapExecTool,
        "impacket": ImpacketTools,
        "metasploit": MetasploitTool,
        "browser": BrowserAutomationTool,
    }


def get_tool_by_name(name: str, **kwargs: Any) -> BaseTool:
    """
    Get a tool instance by name.

    Args:
        name: Tool name (e.g., 'nmap', 'nikto')
        **kwargs: Arguments to pass to tool constructor

    Returns:
        Tool instance

    Raises:
        ValueError: If tool name is not recognized
    """
    tools = get_available_tools()

    if name not in tools:
        raise ValueError(f"Unknown tool: {name}. Available: {list(tools.keys())}")

    approval_gateway = kwargs.pop("approval_gateway", None)
    scope_policy = kwargs.pop("scope_policy", None)
    tool_ctor: Any = tools[name]
    tool = cast(BaseTool, tool_ctor(**kwargs))
    tool.approval_gateway = approval_gateway
    tool.scope_policy = scope_policy
    return tool
