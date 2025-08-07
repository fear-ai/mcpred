"""
Custom exceptions for mcpred security testing.
"""

from typing import Any, Dict, List, Optional


class MCPRedError(Exception):
    """Base exception for mcpred errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class SecurityTestError(MCPRedError):
    """Exception raised during security testing operations."""
    
    def __init__(self, test_type: str, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(f"Security test '{test_type}' failed: {message}", context)
        self.test_type = test_type


class TransportError(MCPRedError):
    """Exception raised during transport operations."""
    
    def __init__(self, transport_type: str, message: str, original_error: Optional[Exception] = None):
        super().__init__(f"Transport '{transport_type}' error: {message}")
        self.transport_type = transport_type
        self.original_error = original_error


class AuthTestError(SecurityTestError):
    """Exception raised during authentication testing."""
    
    def __init__(self, auth_method: str, message: str, response_data: Optional[Dict[str, Any]] = None):
        super().__init__("auth_test", f"Authentication test for '{auth_method}': {message}", response_data)
        self.auth_method = auth_method


class ProtocolFuzzError(SecurityTestError):
    """Exception raised during protocol fuzzing operations."""
    
    def __init__(self, message: str, payload: Optional[Dict[str, Any]] = None):
        super().__init__("protocol_fuzz", message, {"payload": payload})


class DiscoveryError(SecurityTestError):
    """Exception raised during server discovery operations."""
    
    def __init__(self, target: str, message: str, discovery_data: Optional[Dict[str, Any]] = None):
        super().__init__("discovery", f"Discovery failed for '{target}': {message}", discovery_data)
        self.target = target


class SecurityAnalyzedError(MCPRedError):
    """Exception wrapper that includes security analysis of the original error."""
    
    def __init__(self, original_error: Exception, security_analysis: Dict[str, Any]):
        super().__init__(f"Security analysis of error: {str(original_error)}", security_analysis)
        self.original_error = original_error
        self.security_analysis = security_analysis