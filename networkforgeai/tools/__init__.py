"""Offensive security tools integration package."""

from .base_tool import BaseTool, ToolResult, ToolCategory, ToolRiskLevel
from .nmap_tool import NmapTool, MasscanTool
from .web_scanner_tools import NiktoTool, OWASPZAPTool, SQLMapTool
from .password_tools import HydraTool, CrackMapExecTool, ImpacketTools

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
]


def get_available_tools() -> dict:
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
    }


def get_tool_by_name(name: str, **kwargs) -> BaseTool:
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
    
    return tools[name](**kwargs)