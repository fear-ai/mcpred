"""
Pytest configuration and shared fixtures for mcpred tests.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import AsyncGenerator, Dict, Any

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, types
from core.client import MCPTeamClient, SecurityConfig
from core.session import SecSessionManager
from core.transports import SecTransport


def pytest_addoption(parser):
    """Add custom pytest options."""
    parser.addoption(
        "--integration", action="store_true", default=False,
        help="run integration tests"
    )


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "integration: mark test as integration test")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def security_config() -> SecurityConfig:
    """Default security configuration for testing."""
    return SecurityConfig(
        connection_limit=10,
        total_timeout=5,
        response_timeout=2,
        max_fuzz_requests=10,
        malformed_rate=0.5,
    )


@pytest.fixture
def mock_client_session() -> AsyncMock:
    """Mock MCP ClientSession."""
    session = AsyncMock(spec=ClientSession)
    
    # Mock initialization
    session.initialize.return_value = types.InitializeResult(
        protocolVersion="2024-11-05",
        capabilities=types.ServerCapabilities(),
        serverInfo=types.Implementation(name="test-server", version="1.0.0")
    )
    
    # Mock tools listing
    session.list_tools.return_value = types.ListToolsResult(tools=[
        types.Tool(
            name="test_tool",
            description="A test tool",
            inputSchema={"type": "object", "properties": {}}
        )
    ])
    
    # Mock resources listing
    session.list_resources.return_value = types.ListResourcesResult(resources=[
        types.Resource(
            uri="test://resource",
            name="test_resource",
            description="A test resource"
        )
    ])
    
    # Mock prompts listing
    session.list_prompts.return_value = types.ListPromptsResult(prompts=[
        types.Prompt(
            name="test_prompt",
            description="A test prompt"
        )
    ])
    
    # Mock tool call
    session.call_tool.return_value = types.CallToolResult(
        content=[types.TextContent(type="text", text="Test result")]
    )
    
    # Mock resource read
    session.read_resource.return_value = types.ReadResourceResult(
        contents=[types.TextContent(type="text", text="Test content")]
    )
    
    # Mock send_request for custom requests
    session.send_request.return_value = {"result": "test"}
    
    return session


@pytest.fixture
def mock_transport(mock_client_session) -> AsyncMock:
    """Mock SecTransport."""
    transport = AsyncMock(spec=SecTransport)
    transport.target = "http://test-server:8080"
    transport.connected = True
    
    # Mock context manager for connection
    async def mock_connect():
        yield mock_client_session
    
    transport.connect_with_monitoring.return_value.__aenter__ = AsyncMock(return_value=mock_client_session)
    transport.connect_with_monitoring.return_value.__aexit__ = AsyncMock(return_value=None)
    
    # Mock malformed request injection
    transport.inject_malformed_request.return_value = {
        "status": 400,
        "headers": {"Content-Type": "application/json"},
        "text": '{"error": "Bad Request"}'
    }
    
    return transport


@pytest.fixture
def sec_session_manager(mock_client_session) -> SecSessionManager:
    """SecSessionManager with mock underlying session."""
    return SecSessionManager(mock_client_session)


@pytest.fixture
def mcp_team_client(security_config, mock_transport) -> MCPTeamClient:
    """MCPTeamClient with mocked dependencies."""
    client = MCPTeamClient(
        target_url="http://test-server:8080",
        transport_type="http",
        security_config=security_config
    )
    client.transport = mock_transport
    return client


@pytest.fixture
def sample_server_capabilities():
    """Sample server capabilities for testing."""
    return {
        "transport_methods": ["http"],
        "tools": [
            {"name": "echo", "description": "Echo tool"},
            {"name": "file_read", "description": "File reading tool"}
        ],
        "resources": [
            {"uri": "file://test.txt", "name": "test_file", "description": "Test file"},
            {"uri": "config://app.json", "name": "config", "description": "App config"}
        ],
        "prompts": [
            {"name": "greeting", "description": "Greeting prompt"}
        ],
        "server_info": {
            "protocol_version": "2024-11-05",
            "capabilities": {},
            "server_info": {"name": "test-server", "version": "1.0.0"}
        },
        "fingerprint": {},
        "security_issues": []
    }


@pytest.fixture
def sample_security_issues():
    """Sample security issues for testing."""
    return [
        {
            "type": "information_disclosure",
            "severity": "medium",
            "description": "Server reveals internal paths in error messages",
            "pattern": "path"
        },
        {
            "type": "potentially_dangerous_tool",
            "severity": "high", 
            "description": "Tool 'system_exec' may provide dangerous functionality",
            "tool_name": "system_exec"
        }
    ]


@pytest.fixture
def sample_protocol_violations():
    """Sample protocol violations for testing."""
    return [
        {
            "type": "malformed_request_accepted",
            "payload": {"jsonrpc": "1.0"},
            "response": '{"result": "ok"}',
            "request_index": 0
        },
        {
            "type": "server_error",
            "payload": {},
            "response": "Internal Server Error",
            "request_index": 1
        }
    ]


@pytest.fixture
def sample_performance_metrics():
    """Sample performance metrics for testing."""
    return {
        "connection_limit": 50,
        "average_response_time": 0.25,
        "error_rate": 0.05,
        "throughput": 200.0,
        "memory_usage": {"peak_mb": 128, "average_mb": 64},
        "issues": []
    }


class MockAsyncContextManager:
    """Helper for mocking async context managers."""
    
    def __init__(self, return_value):
        self.return_value = return_value
    
    async def __aenter__(self):
        return self.return_value
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None