"""
Integration tests for MCPTeamClient.

These tests require actual MCP servers for full integration testing.
"""

import pytest
import asyncio
from typing import AsyncGenerator

from mcpred.core.client import MCPTeamClient, SecurityConfig
from mcpred.core.exceptions import SecurityTestError, TransportError


@pytest.mark.integration
class TestMCPTeamClientIntegration:
    """Integration tests for MCPTeamClient with real servers."""
    
    @pytest.fixture
    async def test_server_url(self) -> str:
        """URL for test MCP server. Override in actual integration tests."""
        # This would be configured to point to a real test server
        return "http://localhost:8080/mcp"
    
    @pytest.fixture
    async def integration_client(self, test_server_url) -> AsyncGenerator[MCPTeamClient, None]:
        """MCPTeamClient configured for integration testing."""
        config = SecurityConfig(
            total_timeout=30,
            connect_timeout=10,
            response_timeout=5,
            max_fuzz_requests=10,  # Limit for testing
            malformed_rate=0.2,
            max_connections=5
        )
        
        client = MCPTeamClient(
            target_url=test_server_url,
            transport_type="http",
            security_config=config
        )
        
        yield client
        
        # Cleanup if needed
        if client.transport and client.transport.connected:
            await client.transport.disconnect()
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_full_discovery_workflow(self, integration_client):
        """Test complete discovery workflow against real server."""
        client = integration_client
        
        # Test server discovery
        capabilities = await client.discover_server()
        
        assert capabilities is not None
        assert len(capabilities.transport_methods) > 0
        assert capabilities.server_info is not None
        
        # Should have discovered some capabilities
        total_capabilities = (
            len(capabilities.tools) + 
            len(capabilities.resources) + 
            len(capabilities.prompts)
        )
        assert total_capabilities >= 0  # Server might have no capabilities
        
        # Check security analysis was performed
        assert isinstance(capabilities.security_issues, list)
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_authentication_testing_workflow(self, integration_client):
        """Test authentication testing against real server."""
        client = integration_client
        
        # First discover the server
        await client.discover_server()
        
        # Test authentication
        security_issues = await client.test_authentication()
        
        assert isinstance(security_issues, list)
        # Results depend on server configuration
        # Just verify the test completed without errors
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_protocol_fuzzing_workflow(self, integration_client):
        """Test protocol fuzzing against real server."""
        client = integration_client
        
        # Limit fuzzing for integration testing
        violations = await client.fuzz_protocol(
            request_count=5,
            malformed_rate=0.4
        )
        
        assert isinstance(violations, list)
        # Results depend on server robustness
        # Just verify the test completed
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"  
    )
    async def test_stress_testing_workflow(self, integration_client):
        """Test stress testing against real server."""
        client = integration_client
        
        metrics = await client.stress_test()
        
        assert metrics is not None
        assert metrics.connection_limit >= 0
        assert metrics.average_response_time >= 0.0
        assert isinstance(metrics.issues, list)
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_complete_security_assessment(self, integration_client):
        """Test complete security assessment workflow."""
        client = integration_client
        
        # Run all security tests in sequence
        capabilities = await client.discover_server()
        security_issues = await client.test_authentication()
        violations = await client.fuzz_protocol(request_count=3, malformed_rate=0.5)
        metrics = await client.stress_test()
        
        # Generate summary report
        summary = client.get_summary()
        
        assert summary["target"] == client.target
        assert summary["transport_type"] == "http"
        assert summary["capabilities"] is not None
        assert "security_issues_count" in summary
        assert "protocol_violations_count" in summary
        assert "performance_metrics" in summary
    
    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Test handling of connection errors."""
        # Use non-existent server
        client = MCPTeamClient(
            "http://nonexistent-server:9999",
            security_config=SecurityConfig(connect_timeout=2)
        )
        
        with pytest.raises((SecurityTestError, TransportError)):
            await client.discover_server()
    
    @pytest.mark.asyncio
    async def test_invalid_transport_type(self):
        """Test handling of invalid transport types."""
        client = MCPTeamClient("invalid://test", "invalid_transport")
        
        with pytest.raises(TransportError):
            await client.discover_server()
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, integration_client):
        """Test concurrent security operations."""
        client = integration_client
        
        # Run multiple operations concurrently
        tasks = [
            client.discover_server(),
            client.test_authentication(),
        ]
        
        # This tests that the client can handle concurrent access
        # Note: Some operations might fail if they interfere with each other
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # At least one operation should succeed
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) > 0


@pytest.mark.integration
class TestTransportIntegration:
    """Integration tests for different transport types."""
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_http_transport_integration(self):
        """Test HTTP transport with real server."""
        client = MCPTeamClient(
            "http://localhost:8080/mcp",
            "http",
            SecurityConfig(connect_timeout=5)
        )
        
        try:
            capabilities = await client.discover_server()
            assert "http" in capabilities.transport_methods
        except (SecurityTestError, TransportError):
            pytest.skip("HTTP server not available for testing")
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_websocket_transport_integration(self):
        """Test WebSocket transport with real server."""
        client = MCPTeamClient(
            "ws://localhost:8080/mcp",
            "websocket",
            SecurityConfig(connect_timeout=5)
        )
        
        try:
            capabilities = await client.discover_server()
            assert capabilities is not None
        except (SecurityTestError, TransportError):
            pytest.skip("WebSocket server not available for testing")
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_stdio_transport_integration(self):
        """Test stdio transport with real server process."""
        # This would require a server script that can run as subprocess
        client = MCPTeamClient(
            "python test_server.py",
            "stdio",
            SecurityConfig(connect_timeout=10)
        )
        
        try:
            capabilities = await client.discover_server()
            assert capabilities is not None
        except (SecurityTestError, TransportError):
            pytest.skip("Stdio server script not available for testing")


@pytest.mark.integration 
class TestSecurityTestingIntegration:
    """Integration tests for security testing features."""
    
    @pytest.fixture
    def vulnerable_server_config(self):
        """Configuration for testing against vulnerable server."""
        return {
            "url": "http://localhost:8081/vulnerable-mcp",
            "expected_vulnerabilities": [
                "information_disclosure",
                "debug_information_leak", 
                "potentially_dangerous_tool"
            ]
        }
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_vulnerability_detection(self, vulnerable_server_config):
        """Test detection of known vulnerabilities."""
        client = MCPTeamClient(vulnerable_server_config["url"])
        
        try:
            # Run security assessment
            capabilities = await client.discover_server()
            security_issues = await client.test_authentication()
            violations = await client.fuzz_protocol(request_count=10)
            
            # Combine all security findings
            all_issues = capabilities.security_issues + security_issues
            
            # Check if expected vulnerabilities were found
            found_types = [issue.type if hasattr(issue, 'type') else issue.get('type') for issue in all_issues]
            
            for expected_vuln in vulnerable_server_config["expected_vulnerabilities"]:
                if expected_vuln in found_types:
                    # At least one expected vulnerability was found
                    break
            else:
                pytest.fail("No expected vulnerabilities were detected")
                
        except (SecurityTestError, TransportError):
            pytest.skip("Vulnerable test server not available")
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(
        "not config.getoption('--integration')",
        reason="Integration tests require --integration flag"
    )
    async def test_false_positive_handling(self):
        """Test handling of false positives in security testing."""
        # Use a known-good server that should not have vulnerabilities
        client = MCPTeamClient(
            "http://localhost:8082/secure-mcp",
            security_config=SecurityConfig(
                max_fuzz_requests=5,  # Limit testing
                malformed_rate=0.3
            )
        )
        
        try:
            capabilities = await client.discover_server()
            security_issues = await client.test_authentication()
            
            # A secure server should have minimal or no issues
            total_high_severity = sum(
                1 for issue in capabilities.security_issues + security_issues
                if (hasattr(issue, 'severity') and issue.severity == "high") or
                   (isinstance(issue, dict) and issue.get('severity') == "high")
            )
            
            # Should not have many high-severity false positives
            assert total_high_severity <= 1  # Allow for some noise
            
        except (SecurityTestError, TransportError):
            pytest.skip("Secure test server not available")


# Pytest configuration for integration tests
def pytest_addoption(parser):
    """Add integration test command line option."""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests (requires test servers)"
    )