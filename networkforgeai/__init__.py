"""
NetworkForgeAI - Authorized AI-Assisted Penetration Testing Framework

Main package initialization with human-in-the-loop approval system.
"""

__version__ = "0.1.0"
__author__ = "NetworkForgeAI Team"

try:
    from .config import settings
except ImportError:  # Allows lightweight modules to be inspected before extras are installed.
    settings = None

__all__ = ["settings", "__version__"]
