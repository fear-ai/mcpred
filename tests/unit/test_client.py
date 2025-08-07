"""
Unit tests for MCPTeamClient.
"""

import pytest
from unittest.mock import AsyncMock, patch

from mcpred.core.client import MCPTeamClient, SecurityConfig, ServerCapabilities, SecurityIssue, ProtocolViolation, PerformanceMetrics
from mcpred.core.exceptions import SecurityTestError


class TestSecurityConfig:
    """Test SecurityConfig class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SecurityConfig()
        
        assert config.connection_limit == 100
        assert config.total_timeout == 30
        assert config.malformed_rate == 0.3
        assert config.disable_ssl_verify is False
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = SecurityConfig(
            connection_limit=50,
            total_timeout=15,
            disable_ssl_verify=True
        )
        
        assert config.connection_limit == 50
        assert config.total_timeout == 15
        assert config.disable_ssl_verify is True
    
    def test_to_dict(self):
        """Test config serialization to dict."""
        config = SecurityConfig(connection_limit=25)
        config_dict = config.to_dict()
        
        assert isinstance(config_dict, dict)
        assert config_dict["connection_limit"] == 25


class TestServerCapabilities:
    """Test ServerCapabilities class."""
    
    def test_empty_capabilities(self):
        """Test empty capabilities initialization."""
        caps = ServerCapabilities()
        
        assert caps.transport_methods == []
        assert caps.tools == []
        assert caps.resources == []
        assert caps.prompts == []
        assert caps.server_info == {}
        assert caps.fingerprint == {}
        assert caps.security_issues == []
    
    def test_to_dict(self, sample_server_capabilities):
        """Test capabilities serialization."""
        caps = ServerCapabilities()
        caps.transport_methods = ["http"]
        caps.server_info = {"test": "data"}
        
        result = caps.to_dict()
        
        assert isinstance(result, dict)
        assert result["transport_methods"] == ["http"]
        assert result["server_info"] == {"test": "data"}


class TestSecurityIssue:
    """Test SecurityIssue class."""
    
    def test_issue_creation(self):
        """Test creating security issue."""
        issue = SecurityIssue(
            "auth_bypass",
            "high", 
            "Authentication can be bypassed",
            tool_name="admin_tool"
        )
        
        assert issue.type == "auth_bypass"
        assert issue.severity == "high"
        assert issue.description == "Authentication can be bypassed"
        assert issue.details["tool_name"] == "admin_tool"
    
    def test_to_dict(self):
        """Test issue serialization."""
        issue = SecurityIssue("test", "low", "Test issue", extra="data")
        result = issue.to_dict()
        
        assert result["type"] == "test"
        assert result["severity"] == "low"
        assert result["description"] == "Test issue"
        assert result["extra"] == "data"


class TestProtocolViolation:
    """Test ProtocolViolation class."""
    
    def test_violation_creation(self):
        """Test creating protocol violation."""
        violation = ProtocolViolation(
            "malformed_accepted",
            {"test": "payload"},
            "response_data",
            index=1
        )
        
        assert violation.type == "malformed_accepted"
        assert violation.payload == {"test": "payload"}
        assert violation.response == "response_data"
        assert violation.details["index"] == 1
    
    def test_to_dict(self):
        """Test violation serialization."""
        violation = ProtocolViolation("test", {}, "response")
        result = violation.to_dict()
        
        assert result["type"] == "test"
        assert result["payload"] == {}
        assert result["response"] == "response"


class TestPerformanceMetrics:
    """Test PerformanceMetrics class."""
    
    def test_empty_metrics(self):
        """Test empty metrics initialization."""
        metrics = PerformanceMetrics()
        
        assert metrics.connection_limit == 0
        assert metrics.average_response_time == 0.0
        assert metrics.error_rate == 0.0
        assert metrics.throughput == 0.0
        assert metrics.memory_usage == {}
        assert metrics.issues == []
    
    def test_to_dict(self):
        """Test metrics serialization."""
        metrics = PerformanceMetrics()
        metrics.connection_limit = 100
        metrics.error_rate = 0.1
        
        result = metrics.to_dict()
        
        assert result["connection_limit"] == 100
        assert result["error_rate"] == 0.1


class TestMCPTeamClient:
    """Test MCPTeamClient class."""
    
    def test_client_initialization(self):
        """Test client initialization."""
        client = MCPTeamClient(
            "http://test:8080",
            "http",
            SecurityConfig(connection_limit=50)
        )
        
        assert client.target == "http://test:8080"
        assert client.transport_type == "http"
        assert client.security_config.connection_limit == 50
        assert client.transport is None
        assert client.session_manager is None
    
    def test_default_config(self):
        """Test client with default config."""
        client = MCPTeamClient("http://test:8080")
        
        assert client.transport_type == "http"
        assert isinstance(client.security_config, SecurityConfig)
    
    @pytest.mark.asyncio
    async def test_discover_server_success(self, mcp_team_client, mock_client_session):
        """Test successful server discovery."""
        capabilities = await mcp_team_client.discover_server()
        
        assert isinstance(capabilities, ServerCapabilities)
        assert capabilities.transport_methods == ["http"]
        assert len(capabilities.tools) == 1
        assert capabilities.tools[0].name == "test_tool"
        
        # Verify transport connection was established
        mcp_team_client.transport.connect_with_monitoring.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_discover_server_error(self, mcp_team_client):
        """Test discovery with transport error."""
        # Mock transport to raise error
        mcp_team_client.transport.connect_with_monitoring.side_effect = Exception("Connection failed")
        
        with pytest.raises(SecurityTestError) as exc_info:
            await mcp_team_client.discover_server()
        
        assert "discovery" in str(exc_info.value)
        assert "Connection failed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_test_authentication(self, mcp_team_client):
        """Test authentication testing."""
        issues = await mcp_team_client.test_authentication()
        
        assert isinstance(issues, list)
        # Should find at least one issue for unauthorized tool access
        assert any(issue.type == "unauthorized_tool_access" for issue in issues)
    
    @pytest.mark.asyncio
    async def test_fuzz_protocol(self, mcp_team_client):
        """Test protocol fuzzing."""
        violations = await mcp_team_client.fuzz_protocol(request_count=5, malformed_rate=0.8)
        
        assert isinstance(violations, list)
        # Should inject malformed requests based on count and rate
        assert mcp_team_client.transport.inject_malformed_request.call_count >= 1
    
    @pytest.mark.asyncio
    async def test_stress_test(self, mcp_team_client):
        """Test stress testing."""
        with patch.object(mcp_team_client, '_test_connection_limits', return_value=50):
            with patch.object(mcp_team_client, '_test_response_times', return_value=[0.1, 0.2, 0.15]):
                metrics = await mcp_team_client.stress_test()
        
        assert isinstance(metrics, PerformanceMetrics)
        assert metrics.connection_limit == 50
        assert metrics.average_response_time == 0.15
    
    @pytest.mark.asyncio
    async def test_protocol_violation_detection(self, mcp_team_client):
        """Test protocol violation detection."""
        # Test with response that indicates acceptance of malformed request
        response_good = {"status": 400, "text": "Bad Request"}
        response_bad = {"status": 200, "text": "Success"}
        
        assert not mcp_team_client._is_protocol_violation({}, response_good)
        assert mcp_team_client._is_protocol_violation({}, response_bad)
    
    @pytest.mark.asyncio
    async def test_connection_limits_testing(self, mcp_team_client):
        """Test connection limits testing."""
        with patch('mcpred.core.transports.TransportFactory.create_transport') as mock_factory:
            with patch('asyncio.wait_for') as mock_wait:
                # Mock successful connections up to limit
                mock_transport = AsyncMock()
                mock_factory.return_value = mock_transport
                mock_wait.return_value = "mock_connection"
                
                max_conn = await mcp_team_client._test_connection_limits()
                
                # Should test incrementally up to max_concurrent_connections
                assert max_conn >= 0
    
    @pytest.mark.asyncio 
    async def test_response_times_testing(self, mcp_team_client, mock_client_session):
        """Test response times testing."""
        mcp_team_client.session_manager = AsyncMock()
        mcp_team_client.session_manager.initialize = AsyncMock()
        mcp_team_client.session_manager.list_tools = AsyncMock()
        
        response_times = await mcp_team_client._test_response_times()
        
        assert isinstance(response_times, list)
        assert len(response_times) <= 10  # Should test up to 10 requests
    
    def test_get_summary(self, mcp_team_client):
        """Test getting comprehensive summary."""
        summary = mcp_team_client.get_summary()
        
        assert isinstance(summary, dict)
        assert summary["target"] == "http://test-server:8080"
        assert summary["transport_type"] == "http"
        assert "capabilities" in summary
        assert "security_issues_count" in summary
        assert "protocol_violations_count" in summary
    
    @pytest.mark.asyncio
    async def test_error_handling_in_discovery(self, mcp_team_client, mock_client_session):
        """Test error handling during discovery operations."""
        # Make tools listing fail
        mock_client_session.list_tools.side_effect = Exception("Tools unavailable")
        
        capabilities = await mcp_team_client.discover_server()
        
        # Should continue with other operations even if tools fail
        assert isinstance(capabilities, ServerCapabilities)
        assert len(capabilities.resources) == 1  # Resources should still work
    
    @pytest.mark.asyncio
    async def test_security_config_integration(self):
        """Test security config integration with client operations."""
        config = SecurityConfig(
            max_fuzz_requests=20,
            malformed_rate=0.7,
            max_concurrent_connections=10
        )
        
        client = MCPTeamClient("http://test:8080", security_config=config)
        
        assert client.security_config.max_fuzz_requests == 20
        assert client.security_config.malformed_rate == 0.7
        assert client.security_config.max_concurrent_connections == 10