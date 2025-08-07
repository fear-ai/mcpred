"""
Server discovery and enumeration engine.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional

from mcp import ClientSession, types
from mcp.shared.exceptions import McpError

from ..core.exceptions import DiscoveryError
from ..core.session import SecSessionManager


logger = logging.getLogger(__name__)


class ServerFingerprint:
    """Container for server fingerprint information."""
    
    def __init__(self):
        self.server_name: Optional[str] = None
        self.server_version: Optional[str] = None
        self.protocol_version: Optional[str] = None
        self.implementation: Optional[str] = None
        self.capabilities: Dict[str, Any] = {}
        self.transport_features: List[str] = []
        self.security_headers: Dict[str, str] = {}
        self.timing_characteristics: Dict[str, float] = {}


class TransportMethod:
    """Information about available transport methods."""
    
    def __init__(self, method: str, url: str, available: bool = True, **kwargs):
        self.method = method
        self.url = url
        self.available = available
        self.details = kwargs


class DiscoveryEngine:
    """Server discovery and enumeration engine."""
    
    def __init__(self):
        self.discovered_capabilities: Dict[str, Any] = {}
        self.security_findings: List[Dict[str, Any]] = []
        self.fingerprint_data: Optional[ServerFingerprint] = None
    
    async def enumerate_capabilities(self, session: SecSessionManager) -> Dict[str, Any]:
        """Enumerate server capabilities, resources, tools, prompts."""
        logger.info("Starting capability enumeration")
        
        capabilities = {
            "tools": [],
            "resources": [],
            "prompts": [],
            "server_info": {},
            "protocol_info": {}
        }
        
        try:
            # Get initialization info
            if not session.initialized:
                init_result = await session.initialize()
                capabilities["server_info"] = {
                    "protocol_version": init_result.protocolVersion,
                    "server_info": init_result.serverInfo.__dict__ if init_result.serverInfo else {},
                    "capabilities": init_result.capabilities.__dict__ if init_result.capabilities else {}
                }
            
            # Enumerate tools
            try:
                tools_result = await session.list_tools()
                capabilities["tools"] = [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.inputSchema,
                        "security_analysis": self._analyze_tool_security(tool)
                    }
                    for tool in tools_result.tools
                ]
                logger.info(f"Discovered {len(capabilities['tools'])} tools")
            except McpError as e:
                logger.warning(f"Failed to enumerate tools: {e}")
                capabilities["tools_error"] = str(e)
            
            # Enumerate resources
            try:
                resources_result = await session.list_resources()
                capabilities["resources"] = [
                    {
                        "uri": str(resource.uri),
                        "name": resource.name,
                        "description": resource.description,
                        "mime_type": resource.mimeType,
                        "security_analysis": self._analyze_resource_security(resource)
                    }
                    for resource in resources_result.resources
                ]
                logger.info(f"Discovered {len(capabilities['resources'])} resources")
            except McpError as e:
                logger.warning(f"Failed to enumerate resources: {e}")
                capabilities["resources_error"] = str(e)
            
            # Enumerate prompts
            try:
                prompts_result = await session.list_prompts()
                capabilities["prompts"] = [
                    {
                        "name": prompt.name,
                        "description": prompt.description,
                        "arguments": prompt.arguments,
                        "security_analysis": self._analyze_prompt_security(prompt)
                    }
                    for prompt in prompts_result.prompts
                ]
                logger.info(f"Discovered {len(capabilities['prompts'])} prompts")
            except McpError as e:
                logger.warning(f"Failed to enumerate prompts: {e}")
                capabilities["prompts_error"] = str(e)
            
            self.discovered_capabilities = capabilities
            return capabilities
            
        except Exception as e:
            raise DiscoveryError("capability_enumeration", f"Failed to enumerate capabilities: {str(e)}")
    
    async def detect_transport_methods(self, target: str) -> List[TransportMethod]:
        """Detect available transport methods (HTTP, WebSocket, etc.)."""
        logger.info(f"Detecting transport methods for {target}")
        
        detected_methods = []
        
        # Parse target to determine base URL
        base_url = target
        if "://" in target:
            scheme, rest = target.split("://", 1)
            host_port = rest.split("/")[0]
        else:
            scheme = "http"
            host_port = target
        
        # Test common transport methods
        transport_tests = [
            ("http", f"http://{host_port}"),
            ("https", f"https://{host_port}"),
            ("websocket", f"ws://{host_port}"),
            ("websocket_secure", f"wss://{host_port}"),
        ]
        
        for method, url in transport_tests:
            try:
                available = await self._test_transport_availability(method, url)
                detected_methods.append(TransportMethod(method, url, available))
                if available:
                    logger.info(f"Transport {method} available at {url}")
            except Exception as e:
                logger.debug(f"Transport {method} test failed: {e}")
                detected_methods.append(TransportMethod(method, url, False, error=str(e)))
        
        return detected_methods
    
    async def fingerprint_server(self, session: SecSessionManager) -> ServerFingerprint:
        """Fingerprint server implementation and version."""
        logger.info("Starting server fingerprinting")
        
        fingerprint = ServerFingerprint()
        
        try:
            # Get server info from initialization
            if session.initialized:
                # Extract server information from session
                history = session.request_logger.get_request_history()
                init_responses = [h for h in history if h.get("method") == "initialize" and h.get("direction") == "inbound"]
                
                if init_responses:
                    init_data = init_responses[0].get("response", {})
                    if hasattr(init_data, 'serverInfo') and init_data.serverInfo:
                        fingerprint.server_name = init_data.serverInfo.name
                        fingerprint.server_version = init_data.serverInfo.version
                    if hasattr(init_data, 'protocolVersion'):
                        fingerprint.protocol_version = init_data.protocolVersion
                    if hasattr(init_data, 'capabilities') and init_data.capabilities:
                        fingerprint.capabilities = init_data.capabilities.__dict__
            
            # Analyze timing characteristics
            fingerprint.timing_characteristics = await self._analyze_timing_characteristics(session)
            
            # Analyze response patterns for implementation detection
            fingerprint.implementation = await self._detect_implementation(session)
            
            self.fingerprint_data = fingerprint
            return fingerprint
            
        except Exception as e:
            logger.warning(f"Server fingerprinting failed: {e}")
            return fingerprint
    
    def _analyze_tool_security(self, tool: types.Tool) -> Dict[str, Any]:
        """Analyze tool for security implications."""
        analysis = {
            "risk_level": "low",
            "potential_issues": []
        }
        
        tool_name_lower = tool.name.lower()
        
        # Check for high-risk tool names
        high_risk_patterns = ["exec", "eval", "system", "shell", "command", "run", "delete", "rm"]
        medium_risk_patterns = ["file", "read", "write", "admin", "config", "root", "sudo"]
        
        for pattern in high_risk_patterns:
            if pattern in tool_name_lower:
                analysis["risk_level"] = "high"
                analysis["potential_issues"].append({
                    "type": "dangerous_tool_name",
                    "pattern": pattern,
                    "description": f"Tool name contains potentially dangerous pattern: {pattern}"
                })
        
        if analysis["risk_level"] != "high":
            for pattern in medium_risk_patterns:
                if pattern in tool_name_lower:
                    analysis["risk_level"] = "medium"
                    analysis["potential_issues"].append({
                        "type": "elevated_privilege_tool",
                        "pattern": pattern,
                        "description": f"Tool may require elevated privileges: {pattern}"
                    })
        
        # Analyze input schema for injection risks
        if tool.inputSchema:
            schema_analysis = self._analyze_input_schema(tool.inputSchema)
            analysis["input_schema_risks"] = schema_analysis
        
        return analysis
    
    def _analyze_resource_security(self, resource: types.Resource) -> Dict[str, Any]:
        """Analyze resource for security implications."""
        analysis = {
            "risk_level": "low",
            "potential_issues": []
        }
        
        uri_str = str(resource.uri).lower()
        
        # Check for sensitive resource patterns
        sensitive_patterns = [
            "config", "secret", "password", "key", "credential", "token",
            "admin", "root", "private", "internal", ".env", "database"
        ]
        
        for pattern in sensitive_patterns:
            if pattern in uri_str or pattern in resource.name.lower():
                analysis["risk_level"] = "medium"
                analysis["potential_issues"].append({
                    "type": "potentially_sensitive_resource",
                    "pattern": pattern,
                    "description": f"Resource may contain sensitive information: {pattern}"
                })
        
        # Check for file system access patterns
        file_patterns = ["file://", "path:", "/etc/", "/var/", "C:\\", "\\windows\\"]
        for pattern in file_patterns:
            if pattern in uri_str:
                analysis["risk_level"] = "medium"
                analysis["potential_issues"].append({
                    "type": "file_system_access",
                    "pattern": pattern,
                    "description": "Resource may provide file system access"
                })
        
        return analysis
    
    def _analyze_prompt_security(self, prompt: types.Prompt) -> Dict[str, Any]:
        """Analyze prompt for security implications."""
        analysis = {
            "risk_level": "low",
            "potential_issues": []
        }
        
        # Check prompt name for potential security risks
        prompt_name_lower = prompt.name.lower()
        risky_patterns = ["admin", "root", "system", "debug", "internal", "private"]
        
        for pattern in risky_patterns:
            if pattern in prompt_name_lower:
                analysis["risk_level"] = "low"  # Prompts are generally lower risk
                analysis["potential_issues"].append({
                    "type": "privileged_prompt",
                    "pattern": pattern,
                    "description": f"Prompt may be for privileged operations: {pattern}"
                })
        
        return analysis
    
    def _analyze_input_schema(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze input schema for injection risks."""
        analysis = {
            "injection_risks": [],
            "validation_issues": []
        }
        
        # Check for string inputs without validation
        if schema.get("type") == "object" and "properties" in schema:
            for prop_name, prop_schema in schema["properties"].items():
                if prop_schema.get("type") == "string":
                    if "pattern" not in prop_schema and "enum" not in prop_schema:
                        analysis["injection_risks"].append({
                            "property": prop_name,
                            "issue": "String input without pattern validation",
                            "risk": "Potential injection vulnerability"
                        })
        
        return analysis
    
    async def _test_transport_availability(self, method: str, url: str) -> bool:
        """Test if a transport method is available."""
        try:
            if method.startswith("http"):
                import aiohttp
                timeout = aiohttp.ClientTimeout(total=5, connect=2)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as response:
                        # Any response (even error) means transport is available
                        return True
            elif method.startswith("websocket"):
                import aiohttp
                timeout = aiohttp.ClientTimeout(total=5, ws_connect=2)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    try:
                        async with session.ws_connect(url) as ws:
                            return True
                    except aiohttp.ClientError:
                        # Connection refused, but WebSocket is supported
                        return False
            
            return False
            
        except Exception:
            return False
    
    async def _analyze_timing_characteristics(self, session: SecSessionManager) -> Dict[str, float]:
        """Analyze server timing characteristics."""
        timing_data = {}
        
        try:
            # Test response times for different operations
            import time
            
            # Test initialization timing
            start = time.time()
            try:
                await session.list_tools()
                timing_data["tools_list_time"] = time.time() - start
            except:
                pass
            
            # Test resource listing timing
            start = time.time()
            try:
                await session.list_resources()
                timing_data["resources_list_time"] = time.time() - start
            except:
                pass
            
            # Calculate average response time
            times = [t for t in timing_data.values() if t > 0]
            if times:
                timing_data["average_response_time"] = sum(times) / len(times)
        
        except Exception as e:
            logger.debug(f"Timing analysis failed: {e}")
        
        return timing_data
    
    async def _detect_implementation(self, session: SecSessionManager) -> Optional[str]:
        """Detect server implementation based on response patterns."""
        try:
            # Analyze response patterns from request history
            history = session.request_logger.get_request_history()
            
            # Look for implementation-specific patterns
            for entry in history:
                if entry.get("direction") == "inbound":
                    response = entry.get("response")
                    if response and hasattr(response, 'serverInfo'):
                        server_info = response.serverInfo
                        if server_info and hasattr(server_info, 'name'):
                            return server_info.name
            
            # Fallback to generic detection
            return "unknown"
            
        except Exception:
            return None