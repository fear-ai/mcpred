"""
mcpred - MCP Red Team Client

A Python-based command line MCP client for red teaming and security testing.
Exercise and test remote MCP servers to identify vulnerabilities and weaknesses.
"""

__version__ = "0.1.0"
__author__ = "mcpred team"
__description__ = "MCP Red Team Client for security testing"

from .core.client import MCPTeamClient
from .core.exceptions import MCPRedError, SecurityTestError, TransportError

__all__ = [
    "MCPTeamClient",
    "MCPRedError", 
    "SecurityTestError",
    "TransportError",
    "__version__",
]