"""
CLI modules for mcpred.

Contains command-line interface implementation and command handlers.
"""

from .main import main, cli
from .commands import *

__all__ = [
    "main",
    "cli",
]