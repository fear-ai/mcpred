"""
Unit tests for custom exceptions.
"""

import pytest

from mcpred.core.exceptions import (
    MCPRedError,
    SecurityTestError, 
    TransportError,
    AuthTestError,
    ProtocolFuzzError,
    DiscoveryError,
    SecurityAnalyzedError
)


class TestMCPRedError:
    """Test base MCPRedError class."""
    
    def test_basic_error(self):
        """Test basic error creation."""
        error = MCPRedError("Test error message")
        
        assert str(error) == "Test error message"
        assert error.details == {}
    
    def test_error_with_details(self):
        """Test error with details."""
        details = {"key": "value", "code": 123}
        error = MCPRedError("Error with details", details)
        
        assert str(error) == "Error with details"
        assert error.details == details
    
    def test_error_inheritance(self):
        """Test error inherits from Exception."""
        error = MCPRedError("Test")
        
        assert isinstance(error, Exception)


class TestSecurityTestError:
    """Test SecurityTestError class."""
    
    def test_basic_security_error(self):
        """Test basic security test error."""
        error = SecurityTestError("auth_test", "Authentication failed")
        
        assert "Security test 'auth_test' failed: Authentication failed" in str(error)
        assert error.test_type == "auth_test"
    
    def test_security_error_with_context(self):
        """Test security error with context."""
        context = {"target": "test-server", "method": "oauth"}
        error = SecurityTestError("auth_bypass", "Bypass successful", context)
        
        assert error.test_type == "auth_bypass"
        assert error.details == context
    
    def test_security_error_inheritance(self):
        """Test SecurityTestError inherits from MCPRedError."""
        error = SecurityTestError("test", "message")
        
        assert isinstance(error, MCPRedError)
        assert isinstance(error, Exception)


class TestTransportError:
    """Test TransportError class."""
    
    def test_basic_transport_error(self):
        """Test basic transport error."""
        error = TransportError("http", "Connection failed")
        
        assert "Transport 'http' error: Connection failed" in str(error)
        assert error.transport_type == "http"
        assert error.original_error is None
    
    def test_transport_error_with_original(self):
        """Test transport error with original exception."""
        original = ValueError("Original error")
        error = TransportError("websocket", "WebSocket failed", original)
        
        assert error.transport_type == "websocket"
        assert error.original_error == original
    
    def test_transport_error_inheritance(self):
        """Test TransportError inherits from MCPRedError."""
        error = TransportError("stdio", "Process failed")
        
        assert isinstance(error, MCPRedError)


class TestAuthTestError:
    """Test AuthTestError class."""
    
    def test_basic_auth_error(self):
        """Test basic authentication test error."""
        error = AuthTestError("oauth", "Token validation failed")
        
        assert "auth_test" in str(error)
        assert "oauth" in str(error)
        assert "Token validation failed" in str(error)
        assert error.auth_method == "oauth"
    
    def test_auth_error_with_response_data(self):
        """Test auth error with response data."""
        response_data = {"status": 401, "message": "Unauthorized"}
        error = AuthTestError("jwt", "Invalid token", response_data)
        
        assert error.auth_method == "jwt"
        assert error.details == response_data
    
    def test_auth_error_inheritance(self):
        """Test AuthTestError inherits from SecurityTestError."""
        error = AuthTestError("basic", "Failed")
        
        assert isinstance(error, SecurityTestError)
        assert isinstance(error, MCPRedError)
        assert error.test_type == "auth_test"


class TestProtocolFuzzError:
    """Test ProtocolFuzzError class."""
    
    def test_basic_fuzz_error(self):
        """Test basic protocol fuzz error."""
        error = ProtocolFuzzError("Fuzzing payload caused server crash")
        
        assert "protocol_fuzz" in str(error)
        assert "server crash" in str(error)
    
    def test_fuzz_error_with_payload(self):
        """Test fuzz error with payload."""
        payload = {"malformed": "json", "invalid": None}
        error = ProtocolFuzzError("Server accepted malformed request", payload)
        
        assert error.details["payload"] == payload
    
    def test_fuzz_error_inheritance(self):
        """Test ProtocolFuzzError inherits from SecurityTestError."""
        error = ProtocolFuzzError("Test")
        
        assert isinstance(error, SecurityTestError)
        assert error.test_type == "protocol_fuzz"


class TestDiscoveryError:
    """Test DiscoveryError class."""
    
    def test_basic_discovery_error(self):
        """Test basic discovery error."""
        error = DiscoveryError("http://test-server", "Server not responding")
        
        assert "discovery" in str(error)
        assert "http://test-server" in str(error)
        assert "Server not responding" in str(error)
        assert error.target == "http://test-server"
    
    def test_discovery_error_with_data(self):
        """Test discovery error with discovery data."""
        discovery_data = {"attempted_methods": ["tools", "resources"], "timeout": 10}
        error = DiscoveryError("test-server", "Timeout occurred", discovery_data)
        
        assert error.target == "test-server"
        assert error.details == discovery_data
    
    def test_discovery_error_inheritance(self):
        """Test DiscoveryError inherits from SecurityTestError."""
        error = DiscoveryError("server", "Failed")
        
        assert isinstance(error, SecurityTestError)
        assert error.test_type == "discovery"


class TestSecurityAnalyzedError:
    """Test SecurityAnalyzedError class."""
    
    def test_basic_analyzed_error(self):
        """Test basic security analyzed error."""
        original = ValueError("Original error")
        analysis = {"severity": "medium", "type": "information_disclosure"}
        
        error = SecurityAnalyzedError(original, analysis)
        
        assert "Security analysis of error: Original error" in str(error)
        assert error.original_error == original
        assert error.security_analysis == analysis
    
    def test_analyzed_error_with_complex_analysis(self):
        """Test analyzed error with complex security analysis."""
        original = Exception("Database connection failed")
        analysis = {
            "severity": "high",
            "type": "database_disclosure",
            "patterns_found": ["database", "connection"],
            "potential_impact": "Information disclosure about internal systems",
            "recommendations": ["Sanitize error messages", "Log internally only"]
        }
        
        error = SecurityAnalyzedError(original, analysis)
        
        assert error.original_error == original
        assert error.security_analysis["severity"] == "high"
        assert error.security_analysis["type"] == "database_disclosure"
        assert "patterns_found" in error.security_analysis
    
    def test_analyzed_error_inheritance(self):
        """Test SecurityAnalyzedError inherits from MCPRedError."""
        original = Exception("Test")
        analysis = {"test": "data"}
        error = SecurityAnalyzedError(original, analysis)
        
        assert isinstance(error, MCPRedError)
        assert error.details == analysis
    
    def test_analyzed_error_with_mcp_error(self):
        """Test analyzed error wrapping MCP error."""
        from mcp.shared.exceptions import McpError
        from mcp import types
        
        error_data = types.ErrorData(code=-1, message="MCP protocol error")
        original = McpError(error_data)
        analysis = {"mcp_error": True, "protocol_version": "2024-11-05"}
        
        error = SecurityAnalyzedError(original, analysis)
        
        assert isinstance(error.original_error, McpError)
        assert error.security_analysis["mcp_error"] is True


class TestErrorHierarchy:
    """Test error inheritance hierarchy."""
    
    def test_all_errors_inherit_from_mcpred_error(self):
        """Test all custom errors inherit from MCPRedError."""
        errors = [
            SecurityTestError("test", "message"),
            TransportError("http", "error"), 
            AuthTestError("oauth", "failed"),
            ProtocolFuzzError("fuzz error"),
            DiscoveryError("target", "discovery failed"),
            SecurityAnalyzedError(Exception("original"), {"analysis": "data"})
        ]
        
        for error in errors:
            assert isinstance(error, MCPRedError)
            assert isinstance(error, Exception)
    
    def test_security_test_error_subclasses(self):
        """Test SecurityTestError subclasses."""
        auth_error = AuthTestError("oauth", "failed")
        fuzz_error = ProtocolFuzzError("fuzz failed")
        discovery_error = DiscoveryError("target", "discovery failed")
        
        # All should be SecurityTestError instances
        assert isinstance(auth_error, SecurityTestError)
        assert isinstance(fuzz_error, SecurityTestError)
        assert isinstance(discovery_error, SecurityTestError)
        
        # But not instances of each other
        assert not isinstance(auth_error, ProtocolFuzzError)
        assert not isinstance(fuzz_error, AuthTestError)
        assert not isinstance(discovery_error, AuthTestError)
    
    def test_exception_catching(self):
        """Test exception catching with hierarchy."""
        # Should be able to catch specific exceptions
        with pytest.raises(AuthTestError):
            raise AuthTestError("oauth", "failed")
        
        # Should be able to catch parent exceptions
        with pytest.raises(SecurityTestError):
            raise AuthTestError("oauth", "failed")
        
        with pytest.raises(MCPRedError):
            raise TransportError("http", "failed")
        
        with pytest.raises(Exception):
            raise DiscoveryError("target", "failed")
    
    def test_error_details_preservation(self):
        """Test that error details are preserved through hierarchy."""
        details = {"important": "data", "code": 500}
        
        # Test base error
        base_error = MCPRedError("Base error", details)
        assert base_error.details == details
        
        # Test inherited error
        security_error = SecurityTestError("test", "Security error", details)
        assert security_error.details == details
        
        # Test that inherited errors add their own attributes
        transport_error = TransportError("http", "Transport failed")
        assert hasattr(transport_error, 'transport_type')
        assert transport_error.transport_type == "http"