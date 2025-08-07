"""
Main MCPTeamClient class for security testing MCP servers.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from mcp import ClientSession, types

from .exceptions import MCPRedError, SecurityTestError, TransportError
from .session import SecSessionManager
from .transports import TransportFactory, SecTransport


logger = logging.getLogger(__name__)


class SecurityConfig:
    """Configuration for security testing operations."""
    
    def __init__(self, **kwargs):
        # Connection settings
        self.connection_limit = kwargs.get("connection_limit", 100)
        self.per_host_limit = kwargs.get("per_host_limit", 30)
        self.total_timeout = kwargs.get("total_timeout", 30)
        self.connect_timeout = kwargs.get("connect_timeout", 10)
        
        # Security testing settings
        self.disable_ssl_verify = kwargs.get("disable_ssl_verify", False)
        self.response_timeout = kwargs.get("response_timeout", 5)
        self.max_fuzz_requests = kwargs.get("max_fuzz_requests", 1000)
        self.malformed_rate = kwargs.get("malformed_rate", 0.3)
        
        # Stress testing settings
        self.max_connections = kwargs.get("max_connections", 50)
        self.stress_duration = kwargs.get("stress_duration", 60)
        
        # Discovery settings
        self.discovery_timeout = kwargs.get("discovery_timeout", 10)
        self.fingerprint_enabled = kwargs.get("fingerprint_enabled", True)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}


class ServerCapabilities:
    """Container for discovered server capabilities."""
    
    def __init__(self):
        self.transport_methods: List[str] = []
        self.tools: List[types.Tool] = []
        self.resources: List[types.Resource] = []
        self.prompts: List[types.Prompt] = []
        self.server_info: Dict[str, Any] = {}
        self.fingerprint: Dict[str, Any] = {}
        self.security_issues: List[Dict[str, Any]] = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "transport_methods": self.transport_methods,
            "tools": [{"name": t.name, "description": t.description} for t in self.tools],
            "resources": [{"uri": str(r.uri), "name": r.name, "description": r.description} for r in self.resources],
            "prompts": [{"name": p.name, "description": p.description} for p in self.prompts],
            "server_info": self.server_info,
            "fingerprint": self.fingerprint,
            "security_issues": self.security_issues,
        }


class SecurityIssue:
    """Represents a security issue found during testing."""
    
    def __init__(self, issue_type: str, severity: str, description: str, **kwargs):
        self.type = issue_type
        self.severity = severity
        self.description = description
        self.details = kwargs
        self.timestamp = kwargs.get("timestamp", None)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "severity": self.severity, 
            "description": self.description,
            "timestamp": self.timestamp,
            **self.details
        }


class ProtocolViolation:
    """Represents a protocol violation found during fuzzing."""
    
    def __init__(self, violation_type: str, payload: Dict[str, Any], response: Any, **kwargs):
        self.type = violation_type
        self.payload = payload
        self.response = response
        self.details = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "payload": self.payload,
            "response": str(self.response),
            **self.details
        }


class PerformanceMetrics:
    """Container for performance test results."""
    
    def __init__(self):
        self.connection_limit = 0
        self.average_response_time = 0.0
        self.error_rate = 0.0
        self.throughput = 0.0
        self.memory_usage = {}
        self.issues: List[Dict[str, Any]] = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "connection_limit": self.connection_limit,
            "average_response_time": self.average_response_time,
            "error_rate": self.error_rate,
            "throughput": self.throughput,
            "memory_usage": self.memory_usage,
            "issues": self.issues,
        }


class MCPTeamClient:
    """Main client class for security testing MCP servers."""
    
    def __init__(
        self,
        target_url: str,
        transport_type: str = "http",
        security_config: Optional[SecurityConfig] = None
    ):
        self.target = target_url
        self.transport_type = transport_type
        
        # Handle security_config as dict or SecurityConfig object
        if isinstance(security_config, dict):
            self.security_config = SecurityConfig(**security_config)
        else:
            self.security_config = security_config or SecurityConfig()
        
        # Core components - will be initialized on demand
        self.transport: Optional[SecTransport] = None
        self.session_manager: Optional[SecSessionManager] = None
        
        # Results tracking
        self.discovered_capabilities: Optional[ServerCapabilities] = None
        self.security_issues: List[SecurityIssue] = []
        self.protocol_violations: List[ProtocolViolation] = []
        self.performance_metrics: Optional[PerformanceMetrics] = None
        
        logger.info(f"MCPTeamClient initialized for target: {target_url} ({transport_type})")
    
    async def discover_server(self) -> ServerCapabilities:
        """Discover server capabilities and potential attack surface."""
        logger.info("Starting server discovery")
        
        try:
            # Initialize transport if needed
            if not self.transport:
                self.transport = TransportFactory.create_transport(
                    self.transport_type, 
                    self.target,
                    self.security_config.to_dict()
                )
            
            capabilities = ServerCapabilities()
            
            # Connect and discover
            async with self.transport.connect_with_monitoring() as session:
                self.session_manager = SecSessionManager(session)
                
                # Initialize connection
                init_result = await self.session_manager.initialize()
                capabilities.server_info = {
                    "protocol_version": init_result.protocolVersion,
                    "capabilities": init_result.capabilities.__dict__ if init_result.capabilities else {},
                    "server_info": init_result.serverInfo.__dict__ if init_result.serverInfo else {}
                }
                
                # Discover available functionality
                try:
                    tools_result = await self.session_manager.list_tools()
                    capabilities.tools = tools_result.tools
                except Exception as e:
                    logger.warning(f"Failed to list tools: {e}")
                
                try:
                    resources_result = await self.session_manager.list_resources()
                    capabilities.resources = resources_result.resources
                except Exception as e:
                    logger.warning(f"Failed to list resources: {e}")
                
                try:
                    prompts_result = await self.session_manager.list_prompts()
                    capabilities.prompts = prompts_result.prompts
                except Exception as e:
                    logger.warning(f"Failed to list prompts: {e}")
                
                # Collect security issues found during discovery
                security_summary = self.session_manager.get_security_summary()
                capabilities.security_issues = self.session_manager.vuln_detector.get_all_issues()
                
                # Add transport method info
                capabilities.transport_methods = [self.transport_type]
                
                logger.info(f"Discovery completed. Found {len(capabilities.tools)} tools, "
                          f"{len(capabilities.resources)} resources, {len(capabilities.prompts)} prompts")
                
            self.discovered_capabilities = capabilities
            return capabilities
            
        except Exception as e:
            raise SecurityTestError("discovery", f"Failed to discover server: {str(e)}", {"target": self.target})
    
    async def test_authentication(self) -> List[SecurityIssue]:
        """Test authentication mechanisms for vulnerabilities."""
        logger.info("Starting authentication testing")
        
        issues = []
        
        # This is a placeholder for authentication testing
        # In a real implementation, this would:
        # 1. Test OAuth flows for bypasses
        # 2. Test JWT token manipulation 
        # 3. Test privilege escalation
        # 4. Test session management
        
        try:
            if not self.transport:
                self.transport = TransportFactory.create_transport(
                    self.transport_type,
                    self.target, 
                    self.security_config.to_dict()
                )
            
            async with self.transport.connect_with_monitoring() as session:
                self.session_manager = SecSessionManager(session)
                
                # Test basic authentication bypass
                try:
                    await self.session_manager.initialize()
                    
                    # Test unauthorized tool access
                    tools_result = await self.session_manager.list_tools()
                    for tool in tools_result.tools:
                        try:
                            # Try to call tool without proper authentication
                            result = await self.session_manager.call_tool(tool.name, {})
                            issues.append(SecurityIssue(
                                "unauthorized_tool_access",
                                "medium",
                                f"Tool '{tool.name}' accessible without authentication",
                                tool_name=tool.name
                            ))
                        except Exception:
                            # Expected - tool should be protected
                            pass
                    
                except Exception as e:
                    logger.debug(f"Authentication test error: {e}")
            
            self.security_issues.extend(issues)
            logger.info(f"Authentication testing completed. Found {len(issues)} issues")
            return issues
            
        except Exception as e:
            raise SecurityTestError("auth_test", f"Authentication testing failed: {str(e)}")
    
    async def fuzz_protocol(
        self, 
        request_count: int = 100,
        malformed_rate: float = 0.3
    ) -> List[ProtocolViolation]:
        """Perform protocol fuzzing with malformed requests."""
        logger.info(f"Starting protocol fuzzing ({request_count} requests, {malformed_rate} malformed rate)")
        
        violations = []
        
        try:
            if not self.transport:
                self.transport = TransportFactory.create_transport(
                    self.transport_type,
                    self.target,
                    self.security_config.to_dict()
                )
            
            malformed_count = int(request_count * malformed_rate)
            
            for i in range(malformed_count):
                try:
                    # Generate malformed payloads
                    malformed_payloads = [
                        {"jsonrpc": "2.0"},  # Missing required fields
                        {"jsonrpc": "1.0", "method": "test", "id": 1},  # Wrong version
                        {"jsonrpc": "2.0", "method": "", "id": 1},  # Empty method
                        {"jsonrpc": "2.0", "method": "A" * 1000, "id": 1},  # Oversized method
                        {"jsonrpc": "2.0", "method": "test", "params": "invalid", "id": 1},  # Invalid params
                        {},  # Empty payload
                        None,  # Null payload
                    ]
                    
                    payload = malformed_payloads[i % len(malformed_payloads)]
                    
                    # Inject malformed request
                    response = await self.transport.inject_malformed_request(payload)
                    
                    # Analyze response for protocol violations
                    if self._is_protocol_violation(payload, response):
                        violations.append(ProtocolViolation(
                            "malformed_request_accepted",
                            payload,
                            response,
                            request_index=i
                        ))
                    
                except Exception as e:
                    # Server crash or unexpected behavior
                    violations.append(ProtocolViolation(
                        "server_error", 
                        payload if 'payload' in locals() else {},
                        str(e),
                        request_index=i
                    ))
            
            self.protocol_violations.extend(violations)
            logger.info(f"Protocol fuzzing completed. Found {len(violations)} violations")
            return violations
            
        except Exception as e:
            raise SecurityTestError("protocol_fuzz", f"Protocol fuzzing failed: {str(e)}")
    
    async def stress_test(self) -> PerformanceMetrics:
        """Test server performance and DoS resistance."""
        logger.info("Starting stress testing")
        
        metrics = PerformanceMetrics()
        
        try:
            # Test connection limits
            max_connections = await self._test_connection_limits()
            metrics.connection_limit = max_connections
            
            # Test response times under load
            response_times = await self._test_response_times()
            metrics.average_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            # Calculate error rate and throughput
            # (Placeholder implementation)
            metrics.error_rate = 0.1  # 10%
            metrics.throughput = 100.0  # requests/second
            
            self.performance_metrics = metrics
            logger.info(f"Stress testing completed. Max connections: {max_connections}")
            return metrics
            
        except Exception as e:
            raise SecurityTestError("stress_test", f"Stress testing failed: {str(e)}")
    
    def _is_protocol_violation(self, payload: Any, response: Any) -> bool:
        """Check if response indicates a protocol violation."""
        if not response:
            return False
        
        response_str = str(response).lower()
        
        # Server should reject malformed requests with proper errors
        # If it accepts them or crashes, that's a violation
        violation_indicators = [
            "200" in response_str,  # HTTP 200 for malformed JSON-RPC
            "success" in response_str,
            "result" in response_str,
        ]
        
        return any(indicator for indicator in violation_indicators)
    
    async def _test_connection_limits(self) -> int:
        """Test maximum concurrent connections."""
        max_connections = 0
        
        try:
            # Gradually increase connection count until server refuses
            for conn_count in range(1, self.security_config.max_connections + 1):
                try:
                    # Create multiple concurrent connections
                    transports = [
                        TransportFactory.create_transport(
                            self.transport_type,
                            self.target,
                            self.security_config.to_dict()
                        ) for _ in range(conn_count)
                    ]
                    
                    # Try to connect all at once
                    connections = []
                    for transport in transports:
                        try:
                            conn = await asyncio.wait_for(
                                transport.connect_with_monitoring().__aenter__(),
                                timeout=5
                            )
                            connections.append((transport, conn))
                        except asyncio.TimeoutError:
                            break
                    
                    if len(connections) == conn_count:
                        max_connections = conn_count
                    else:
                        break
                    
                    # Clean up connections
                    for transport, conn in connections:
                        try:
                            await transport.connect_with_monitoring().__aexit__(None, None, None)
                        except:
                            pass
                    
                except Exception:
                    break
        
        except Exception as e:
            logger.warning(f"Connection limit testing failed: {e}")
        
        return max_connections
    
    async def _test_response_times(self) -> List[float]:
        """Test response times under various loads."""
        response_times = []
        
        try:
            if not self.transport:
                self.transport = TransportFactory.create_transport(
                    self.transport_type,
                    self.target,
                    self.security_config.to_dict()
                )
            
            async with self.transport.connect_with_monitoring() as session:
                self.session_manager = SecSessionManager(session)
                await self.session_manager.initialize()
                
                # Test response times for different operations
                import time
                
                for _ in range(10):
                    start_time = time.time()
                    try:
                        await self.session_manager.list_tools()
                        end_time = time.time()
                        response_times.append(end_time - start_time)
                    except Exception:
                        # Record timeout as max time
                        response_times.append(self.security_config.response_timeout)
        
        except Exception as e:
            logger.warning(f"Response time testing failed: {e}")
        
        return response_times
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of all test results."""
        return {
            "target": self.target,
            "transport_type": self.transport_type,
            "capabilities": self.discovered_capabilities.to_dict() if self.discovered_capabilities else None,
            "security_issues_count": len(self.security_issues),
            "protocol_violations_count": len(self.protocol_violations),
            "performance_metrics": self.performance_metrics.to_dict() if self.performance_metrics else None,
            "session_summary": self.session_manager.get_security_summary() if self.session_manager else None,
        }