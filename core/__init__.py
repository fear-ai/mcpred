"""
Core module for mcpred.

Contains the main client implementation, session management, and transport handling.
"""

from .client import MCPTeamClient
from .session import SecSessionManager
from .transports import TransportFactory, SecTransport, HTTPSecTransport, StdioSecTransport, WSSecTransport
from .exceptions import MCPRedError, SecurityTestError, TransportError, AuthTestError

__all__ = [
    "MCPTeamClient",
    "SecSessionManager", 
    "TransportFactory",
    "SecTransport",
    "HTTPSecTransport",
    "StdioSecTransport", 
    "WSSecTransport",
    "MCPRedError",
    "SecurityTestError",
    "TransportError",
    "AuthTestError",
]