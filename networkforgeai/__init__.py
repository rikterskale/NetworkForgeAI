"""
NetworkForgeAI - Authorized AI-Assisted Penetration Testing Framework

Main package initialization with human-in-the-loop approval system.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "NetworkForgeAI Team"

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Settings

settings: Settings | None
try:
    from .config import settings as loaded_settings

    settings = loaded_settings
except ImportError:  # Allows lightweight modules to be inspected before extras are installed.
    settings = None

__all__ = ["settings", "__version__"]
