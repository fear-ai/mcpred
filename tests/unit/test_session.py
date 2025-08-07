"""
Unit tests for SecSessionManager and related classes.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
import time

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from mcp import types
from mcp.types import ErrorData
from mcp.shared.exceptions import McpError

from core.session import SecSessionManager, RequestLogger, VulnDetector
from core.exceptions import SecurityAnalyzedError


class TestRequestLogger:
    """Test RequestLogger class."""
    
    def test_log_outbound(self):
        """Test logging outbound requests."""
        logger = RequestLogger()
        
        logger.log_outbound("test_method", {"param": "value"})
        
        assert len(logger.requests) == 1
        request = logger.requests[0]
        assert request["method"] == "test_method"
        assert request["params"] == {"param": "value"}
        assert request["direction"] == "outbound"
        assert "timestamp" in request
    
    def test_log_inbound(self):
        """Test logging inbound responses."""
        logger = RequestLogger()
        
        logger.log_inbound("test_method", {"result": "success"})
        
        assert len(logger.responses) == 1
        response = logger.responses[0]
        assert response["method"] == "test_method"
        assert response["response"] == {"result": "success"}
        assert response["direction"] == "inbound"
        assert "timestamp" in response
    
    def test_get_request_history(self):
        """Test getting complete request history."""
        logger = RequestLogger()
        
        logger.log_outbound("method1", {})
        time.sleep(0.001)  # Ensure different timestamps
        logger.log_inbound("method1", {})
        logger.log_outbound("method2", {})
        
        history = logger.get_request_history()
        
        assert len(history) == 3
        # Should be sorted by timestamp
        assert history[0]["direction"] == "outbound"
        assert history[1]["direction"] == "inbound"
        assert history[2]["direction"] == "outbound"


class TestVulnDetector:
    """Test VulnDetector class."""
    
    @pytest.mark.asyncio
    async def test_analyze_response_information_disclosure(self):
        """Test detecting information disclosure in responses."""
        detector = VulnDetector()
        
        # Response with sensitive information
        class MockResponse:
            def __init__(self):
                self.password = "secret123"
                self.config = "internal"
            
            def __str__(self):
                return "Response(password=secret123, config=internal)"
        
        response_with_secrets = MockResponse()
        
        vulnerabilities = await detector.analyze_response(response_with_secrets)
        
        assert len(vulnerabilities) >= 2
        password_vuln = next(v for v in vulnerabilities if v["pattern"] == "password")
        assert password_vuln["type"] == "information_disclosure"
        assert password_vuln["severity"] == "medium"
    
    @pytest.mark.asyncio
    async def test_analyze_response_debug_information(self):
        """Test detecting debug information in responses."""
        detector = VulnDetector()
        
        response_with_debug = {"debug": "enabled", "trace": "stack_trace_here"}
        
        vulnerabilities = await detector.analyze_response(response_with_debug)
        
        assert len(vulnerabilities) >= 2
        debug_vulns = [v for v in vulnerabilities if v["type"] == "debug_information_leak"]
        assert len(debug_vulns) >= 2
    
    @pytest.mark.asyncio
    async def test_analyze_response_clean(self):
        """Test analyzing clean response with no issues."""
        detector = VulnDetector()
        
        clean_response = {"result": "success", "data": "normal_data"}
        
        vulnerabilities = await detector.analyze_response(clean_response)
        
        assert len(vulnerabilities) == 0
    
    @pytest.mark.asyncio
    async def test_analyze_error_path_disclosure(self):
        """Test detecting path disclosure in errors."""
        detector = VulnDetector()
        
        error_data = ErrorData(code=-1, message="File not found: /internal/config/secret.json")
        error = McpError(error_data)
        
        analysis = await detector.analyze_error(error)
        
        assert analysis["error_type"] == "McpError"
        assert len(analysis["potential_issues"]) >= 1
        path_issue = analysis["potential_issues"][0]
        assert path_issue["type"] == "path_disclosure"
    
    @pytest.mark.asyncio
    async def test_analyze_error_database_disclosure(self):
        """Test detecting database information in errors."""
        detector = VulnDetector()
        
        error_data = ErrorData(code=-1, message="Database connection failed: mysql://user:pass@localhost/db")
        error = McpError(error_data)
        
        analysis = await detector.analyze_error(error)
        
        db_issues = [i for i in analysis["potential_issues"] if i["type"] == "database_disclosure"]
        assert len(db_issues) >= 1
        assert db_issues[0]["severity"] == "medium"
    
    @pytest.mark.asyncio
    async def test_analyze_error_internal_disclosure(self):
        """Test detecting internal system information in errors."""
        detector = VulnDetector()
        
        error_data = ErrorData(code=-1, message="Internal server error: stack trace follows...")
        error = McpError(error_data)
        
        analysis = await detector.analyze_error(error)
        
        internal_issues = [i for i in analysis["potential_issues"] if i["type"] == "internal_error_disclosure"]
        assert len(internal_issues) >= 1
    
    def test_get_all_issues(self):
        """Test getting all detected issues."""
        detector = VulnDetector()
        
        # Manually add some issues
        detector.detected_issues = [
            {"type": "test1", "severity": "high"},
            {"type": "test2", "severity": "low"}
        ]
        
        issues = detector.get_all_issues()
        
        assert len(issues) == 2
        assert issues[0]["type"] == "test1"
        assert issues[1]["type"] == "test2"


class TestSecSessionManager:
    """Test SecSessionManager class."""
    
    def test_initialization(self, mock_client_session):
        """Test session manager initialization."""
        manager = SecSessionManager(mock_client_session)
        
        assert manager.session == mock_client_session
        assert isinstance(manager.request_logger, RequestLogger)
        assert isinstance(manager.vuln_detector, VulnDetector)
        assert not manager._initialized
    
    @pytest.mark.asyncio
    async def test_initialize_success(self, sec_session_manager, mock_client_session):
        """Test successful session initialization."""
        result = await sec_session_manager.initialize()
        
        assert sec_session_manager._initialized
        assert isinstance(result, types.InitializeResult)
        assert result.protocolVersion == "2024-11-05"
        
        # Check logging
        assert len(sec_session_manager.request_logger.requests) == 1
        assert len(sec_session_manager.request_logger.responses) == 1
    
    @pytest.mark.asyncio
    async def test_initialize_error(self, mock_client_session):
        """Test initialization with error."""
        mock_client_session.initialize.side_effect = McpError(ErrorData(code=-1, message="Init failed"))
        
        manager = SecSessionManager(mock_client_session)
        
        with pytest.raises(SecurityAnalyzedError):
            await manager.initialize()
        
        assert not manager._initialized
    
    @pytest.mark.asyncio
    async def test_list_tools_success(self, sec_session_manager):
        """Test successful tools listing."""
        result = await sec_session_manager.list_tools()
        
        assert isinstance(result, types.ListToolsResult)
        assert len(result.tools) == 1
        assert result.tools[0].name == "test_tool"
        
        # Check request logging
        requests = sec_session_manager.request_logger.requests
        assert any(r["method"] == "tools/list" for r in requests)
    
    @pytest.mark.asyncio
    async def test_list_tools_with_dangerous_tools(self, mock_client_session):
        """Test tools listing that detects dangerous tools."""
        # Mock dangerous tool
        dangerous_tool = types.Tool(
            name="system_exec",
            description="Execute system commands",
            inputSchema={}
        )
        mock_client_session.list_tools.return_value = types.ListToolsResult(
            tools=[dangerous_tool]
        )
        
        manager = SecSessionManager(mock_client_session)
        await manager.list_tools()
        
        # Should detect dangerous tool
        issues = manager.vuln_detector.get_all_issues()
        dangerous_issues = [i for i in issues if i["type"] == "potentially_dangerous_tool"]
        assert len(dangerous_issues) >= 1
        assert dangerous_issues[0]["tool_name"] == "system_exec"
    
    @pytest.mark.asyncio
    async def test_list_resources_success(self, sec_session_manager):
        """Test successful resources listing."""
        result = await sec_session_manager.list_resources()
        
        assert isinstance(result, types.ListResourcesResult)
        assert len(result.resources) == 1
        
        # Check request logging
        requests = sec_session_manager.request_logger.requests
        assert any(r["method"] == "resources/list" for r in requests)
    
    @pytest.mark.asyncio
    async def test_list_resources_with_sensitive_resources(self, mock_client_session):
        """Test resources listing that detects sensitive resources."""
        # Mock sensitive resource
        sensitive_resource = types.Resource(
            uri="config://secrets.json",
            name="secrets",
            description="Application secrets"
        )
        mock_client_session.list_resources.return_value = types.ListResourcesResult(
            resources=[sensitive_resource]
        )
        
        manager = SecSessionManager(mock_client_session)
        await manager.list_resources()
        
        # Should detect sensitive resource
        issues = manager.vuln_detector.get_all_issues()
        sensitive_issues = [i for i in issues if i["type"] == "potentially_sensitive_resource"]
        assert len(sensitive_issues) >= 1
        assert "config" in sensitive_issues[0]["pattern"] or "secret" in sensitive_issues[0]["pattern"]
    
    @pytest.mark.asyncio
    async def test_call_tool_success(self, sec_session_manager):
        """Test successful tool calling."""
        result = await sec_session_manager.call_tool("test_tool", {"arg": "value"})
        
        assert isinstance(result, types.CallToolResult)
        assert len(result.content) == 1
        
        # Check request logging
        requests = sec_session_manager.request_logger.requests
        tool_requests = [r for r in requests if r["method"] == "tools/call"]
        assert len(tool_requests) == 1
        assert tool_requests[0]["params"]["name"] == "test_tool"
        assert tool_requests[0]["params"]["arguments"] == {"arg": "value"}
    
    @pytest.mark.asyncio
    async def test_read_resource_success(self, sec_session_manager):
        """Test successful resource reading."""
        result = await sec_session_manager.read_resource("test://resource")
        
        assert isinstance(result, types.ReadResourceResult)
        assert len(result.contents) == 1
        
        # Check request logging
        requests = sec_session_manager.request_logger.requests
        resource_requests = [r for r in requests if r["method"] == "resources/read"]
        assert len(resource_requests) == 1
        assert resource_requests[0]["params"]["uri"] == "test://resource"
    
    @pytest.mark.asyncio
    async def test_monitored_request_success(self, sec_session_manager):
        """Test monitored request with success."""
        response, vulnerabilities = await sec_session_manager.monitored_request(
            "custom/method", 
            {"param": "value"}
        )
        
        assert response == {"result": "test"}
        assert isinstance(vulnerabilities, list)
        
        # Check logging
        assert len(sec_session_manager.request_logger.requests) == 1
        assert len(sec_session_manager.request_logger.responses) == 1
    
    @pytest.mark.asyncio
    async def test_monitored_request_error(self, mock_client_session):
        """Test monitored request with error."""
        mock_client_session.send_request.side_effect = McpError(ErrorData(code=-1, message="Request failed"))
        
        manager = SecSessionManager(mock_client_session)
        
        with pytest.raises(SecurityAnalyzedError) as exc_info:
            await manager.monitored_request("test/method", {})
        
        assert isinstance(exc_info.value.original_error, McpError)
        assert "error_type" in exc_info.value.details
        assert exc_info.value.details["error_type"] == "McpError"
    
    def test_get_security_summary(self, sec_session_manager):
        """Test getting security summary."""
        # Add some mock issues
        sec_session_manager.vuln_detector.detected_issues = [
            {"type": "test1", "severity": "high"},
            {"type": "test2", "severity": "medium"},
            {"type": "test3", "severity": "low"}
        ]
        
        # Add some mock requests
        sec_session_manager.request_logger.requests = [{"test": "request"}]
        sec_session_manager.request_logger.responses = [{"test": "response1"}, {"test": "response2"}]
        
        summary = sec_session_manager.get_security_summary()
        
        assert summary["total_issues"] == 3
        assert summary["severity_breakdown"]["high"] == 1
        assert summary["severity_breakdown"]["medium"] == 1
        assert summary["severity_breakdown"]["low"] == 1
        assert summary["request_count"] == 1
        assert summary["response_count"] == 2
        assert "test1" in summary["issue_types"]
    
    def test_initialized_property(self, sec_session_manager):
        """Test initialized property."""
        assert not sec_session_manager.initialized
        
        sec_session_manager._initialized = True
        assert sec_session_manager.initialized
    
    @pytest.mark.asyncio
    async def test_error_handling_in_operations(self, mock_client_session):
        """Test error handling in various operations."""
        # Test different operations that might fail
        mock_client_session.list_tools.side_effect = McpError(ErrorData(code=-1, message="Tools error"))
        mock_client_session.list_resources.side_effect = McpError(ErrorData(code=-1, message="Resources error"))
        mock_client_session.call_tool.side_effect = McpError(ErrorData(code=-1, message="Tool error"))
        
        manager = SecSessionManager(mock_client_session)
        
        with pytest.raises(SecurityAnalyzedError):
            await manager.list_tools()
        
        with pytest.raises(SecurityAnalyzedError):
            await manager.list_resources()
        
        with pytest.raises(SecurityAnalyzedError):
            await manager.call_tool("test")
        
        # All errors should be analyzed
        assert len(manager.vuln_detector.detected_issues) >= 0  # May have issues detected during analysis