"""
Security-enhanced session management for MCP connections.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from mcp import ClientSession, types
from mcp.shared.exceptions import McpError

from .exceptions import SecurityAnalyzedError


logger = logging.getLogger(__name__)


class RequestLogger:
    """Logger for MCP requests and responses."""
    
    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []
    
    def log_outbound(self, method: str, params: Dict[str, Any]) -> None:
        """Log outbound request."""
        request_data = {
            "timestamp": time.time(),
            "method": method,
            "params": params,
            "direction": "outbound"
        }
        self.requests.append(request_data)
        logger.debug(f"Outbound request: {method} with params: {params}")
    
    def log_inbound(self, method: str, response: Any) -> None:
        """Log inbound response."""
        response_data = {
            "timestamp": time.time(),
            "method": method,
            "response": response,
            "direction": "inbound"
        }
        self.responses.append(response_data)
        logger.debug(f"Inbound response for {method}: {response}")
    
    def get_request_history(self) -> List[Dict[str, Any]]:
        """Get complete request/response history."""
        return sorted(
            self.requests + self.responses,
            key=lambda x: x["timestamp"]
        )


class VulnDetector:
    """Vulnerability detection and analysis."""
    
    def __init__(self):
        self.detected_issues: List[Dict[str, Any]] = []
    
    async def analyze_response(self, response: Any) -> List[Dict[str, Any]]:
        """Analyze response for potential vulnerabilities."""
        vulnerabilities = []
        
        # Check for information disclosure in responses
        if hasattr(response, '__dict__'):
            response_str = str(response)
            
            # Look for sensitive information patterns
            sensitive_patterns = [
                "password", "secret", "key", "token", "credential",
                "admin", "root", "config", "internal", "private"
            ]
            
            for pattern in sensitive_patterns:
                if pattern.lower() in response_str.lower():
                    vulnerabilities.append({
                        "type": "information_disclosure",
                        "severity": "medium",
                        "pattern": pattern,
                        "description": f"Response may contain sensitive information: {pattern}",
                        "response_snippet": response_str[:200]
                    })
        
        # Check response structure for unusual patterns
        if isinstance(response, dict):
            # Look for debug information
            debug_keys = ["debug", "trace", "stack", "error_detail", "internal"]
            for key in debug_keys:
                if key in response:
                    vulnerabilities.append({
                        "type": "debug_information_leak",
                        "severity": "low",
                        "key": key,
                        "description": f"Response contains debug information in key: {key}"
                    })
        
        self.detected_issues.extend(vulnerabilities)
        return vulnerabilities
    
    async def analyze_error(self, error: McpError) -> Dict[str, Any]:
        """Analyze error for security implications."""
        analysis = {
            "error_type": type(error).__name__,
            "message": str(error),
            "potential_issues": []
        }
        
        error_msg = str(error).lower()
        
        # Check for information disclosure in error messages
        if any(pattern in error_msg for pattern in ["file not found", "permission denied", "path"]):
            analysis["potential_issues"].append({
                "type": "path_disclosure",
                "severity": "low",
                "description": "Error message may reveal file system information"
            })
        
        if any(pattern in error_msg for pattern in ["database", "sql", "connection"]):
            analysis["potential_issues"].append({
                "type": "database_disclosure",
                "severity": "medium", 
                "description": "Error message may reveal database information"
            })
        
        if "internal" in error_msg or "stack" in error_msg:
            analysis["potential_issues"].append({
                "type": "internal_error_disclosure",
                "severity": "medium",
                "description": "Error message may reveal internal system information"
            })
        
        return analysis
    
    def get_all_issues(self) -> List[Dict[str, Any]]:
        """Get all detected security issues."""
        return self.detected_issues


class SecSessionManager:
    """Wrapper around MCP ClientSession with security monitoring."""
    
    def __init__(self, official_session: ClientSession):
        self.session = official_session
        self.request_logger = RequestLogger()
        self.vuln_detector = VulnDetector()
        self._initialized = False
    
    async def initialize(self) -> types.InitializeResult:
        """Initialize session with monitoring."""
        try:
            result = await self.session.initialize()
            self._initialized = True
            
            # Log initialization
            self.request_logger.log_outbound("initialize", {})
            self.request_logger.log_inbound("initialize", result)
            
            # Analyze initialization response for vulnerabilities
            await self.vuln_detector.analyze_response(result)
            
            return result
            
        except McpError as e:
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def list_tools(self) -> types.ListToolsResult:
        """List tools with security analysis."""
        try:
            result = await self.session.list_tools()
            
            self.request_logger.log_outbound("tools/list", {})
            self.request_logger.log_inbound("tools/list", result)
            
            # Analyze tools for potential security issues
            await self._analyze_tools(result.tools)
            
            return result
            
        except McpError as e:
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def list_resources(self) -> types.ListResourcesResult:
        """List resources with security analysis."""
        try:
            result = await self.session.list_resources()
            
            self.request_logger.log_outbound("resources/list", {})
            self.request_logger.log_inbound("resources/list", result)
            
            # Analyze resources for potential security issues
            await self._analyze_resources(result.resources)
            
            return result
            
        except McpError as e:
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def list_prompts(self) -> types.ListPromptsResult:
        """List prompts with security analysis."""
        try:
            result = await self.session.list_prompts()
            
            self.request_logger.log_outbound("prompts/list", {})
            self.request_logger.log_inbound("prompts/list", result)
            
            await self.vuln_detector.analyze_response(result)
            
            return result
            
        except McpError as e:
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> types.CallToolResult:
        """Call tool with security monitoring."""
        arguments = arguments or {}
        
        try:
            result = await self.session.call_tool(name, arguments)
            
            self.request_logger.log_outbound("tools/call", {"name": name, "arguments": arguments})
            self.request_logger.log_inbound("tools/call", result)
            
            await self.vuln_detector.analyze_response(result)
            
            return result
            
        except McpError as e:
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def read_resource(self, uri: str) -> types.ReadResourceResult:
        """Read resource with security monitoring."""
        try:
            result = await self.session.read_resource(uri)
            
            self.request_logger.log_outbound("resources/read", {"uri": uri})
            self.request_logger.log_inbound("resources/read", result)
            
            await self.vuln_detector.analyze_response(result)
            
            return result
            
        except McpError as e:
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def monitored_request(self, method: str, params: Dict[str, Any]) -> Tuple[Any, List[Dict[str, Any]]]:
        """Make request with comprehensive security monitoring and analysis."""
        self.request_logger.log_outbound(method, params)
        
        try:
            # Make the request using the underlying session
            response = await self.session.send_request(method, params)
            self.request_logger.log_inbound(method, response)
            
            # Analyze response for vulnerabilities
            vulnerabilities = await self.vuln_detector.analyze_response(response)
            
            return response, vulnerabilities
            
        except McpError as e:
            # Analyze error for information disclosure
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
    
    async def _analyze_tools(self, tools: List[types.Tool]) -> None:
        """Analyze available tools for security implications."""
        for tool in tools:
            # Check for potentially dangerous tool names
            dangerous_patterns = [
                "exec", "eval", "system", "shell", "command", "run",
                "file", "read", "write", "delete", "admin", "config"
            ]
            
            tool_name_lower = tool.name.lower()
            for pattern in dangerous_patterns:
                if pattern in tool_name_lower:
                    self.vuln_detector.detected_issues.append({
                        "type": "potentially_dangerous_tool",
                        "severity": "medium",
                        "tool_name": tool.name,
                        "pattern": pattern,
                        "description": f"Tool '{tool.name}' may provide dangerous functionality"
                    })
    
    async def _analyze_resources(self, resources: List[types.Resource]) -> None:
        """Analyze available resources for security implications."""
        for resource in resources:
            # Check for sensitive resource URIs
            uri_str = str(resource.uri)
            sensitive_patterns = [
                "config", "secret", "password", "key", "credential",
                "admin", "root", "private", "internal"
            ]
            
            for pattern in sensitive_patterns:
                if pattern in uri_str.lower():
                    self.vuln_detector.detected_issues.append({
                        "type": "potentially_sensitive_resource",
                        "severity": "low",
                        "resource_uri": uri_str,
                        "pattern": pattern,
                        "description": f"Resource URI may reference sensitive data: {pattern}"
                    })
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get summary of all security findings."""
        issues = self.vuln_detector.get_all_issues()
        
        summary = {
            "total_issues": len(issues),
            "severity_breakdown": {
                "high": len([i for i in issues if i.get("severity") == "high"]),
                "medium": len([i for i in issues if i.get("severity") == "medium"]),
                "low": len([i for i in issues if i.get("severity") == "low"]),
            },
            "issue_types": list(set(i.get("type") for i in issues)),
            "request_count": len(self.request_logger.requests),
            "response_count": len(self.request_logger.responses),
        }
        
        return summary
    
    @property
    def initialized(self) -> bool:
        """Check if session is initialized."""
        return self._initialized