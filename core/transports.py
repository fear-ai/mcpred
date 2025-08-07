"""
Transport implementations for security-enhanced MCP connections.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import Any, AsyncContextManager, Dict, Optional

import aiohttp
from mcp import ClientSession
from mcp.client import sse, stdio, websocket

from .exceptions import TransportError


class SecTransport(ABC):
    """Base class for security-enhanced MCP transports."""
    
    def __init__(self, target: str, security_config: Optional[Dict[str, Any]] = None):
        self.target = target
        self.security_config = security_config or {}
        self._connected = False
        self._session: Optional[ClientSession] = None
    
    @property
    def connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected
    
    @abstractmethod
    async def connect_with_monitoring(self) -> AsyncContextManager[ClientSession]:
        """Connect with security monitoring capabilities."""
    
    @abstractmethod
    async def inject_malformed_request(self, payload: Dict[str, Any]) -> Any:
        """Inject malformed requests for fuzzing."""
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect and cleanup resources."""


class HTTPSecTransport(SecTransport):
    """HTTP transport with security testing capabilities."""
    
    def __init__(self, target: str, security_config: Optional[Dict[str, Any]] = None):
        super().__init__(target, security_config)
        self.connector: Optional[aiohttp.TCPConnector] = None
        self.client_session: Optional[aiohttp.ClientSession] = None
    
    @asynccontextmanager
    async def connect_with_monitoring(self) -> AsyncContextManager[ClientSession]:
        """Create HTTP connection with request/response monitoring."""
        try:
            # Configure connector with security testing options
            connector_kwargs = {
                "limit": self.security_config.get("connection_limit", 100),
                "limit_per_host": self.security_config.get("per_host_limit", 30),
                "ttl_dns_cache": self.security_config.get("dns_cache_ttl", 300),
            }
            
            # Disable SSL verification if configured for testing
            if self.security_config.get("disable_ssl_verify", False):
                connector_kwargs["verify_ssl"] = False
            
            self.connector = aiohttp.TCPConnector(**connector_kwargs)
            
            # Configure session with custom timeouts
            timeout = aiohttp.ClientTimeout(
                total=self.security_config.get("total_timeout", 30),
                connect=self.security_config.get("connect_timeout", 10),
            )
            
            self.client_session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=timeout
            )
            
            # Create MCP session over HTTP
            read, write = await sse.sse_client(self.target, self.client_session)
            
            mcp_session = ClientSession(read, write)
            self._session = mcp_session
            self._connected = True
            
            yield mcp_session
            
        except Exception as e:
            raise TransportError("http", f"Failed to connect: {str(e)}", e)
        finally:
            await self.disconnect()
    
    async def inject_malformed_request(self, payload: Dict[str, Any]) -> Any:
        """Inject malformed HTTP requests for testing."""
        if not self.client_session:
            raise TransportError("http", "Not connected")
        
        try:
            # Inject malformed JSON payload
            malformed_json = json.dumps(payload) if payload else '{"malformed"'
            
            async with self.client_session.post(
                self.target,
                data=malformed_json,
                headers={"Content-Type": "application/json"}
            ) as response:
                return {
                    "status": response.status,
                    "headers": dict(response.headers),
                    "text": await response.text() if response.status != 204 else ""
                }
        except Exception as e:
            raise TransportError("http", f"Malformed request failed: {str(e)}", e)
    
    async def disconnect(self) -> None:
        """Disconnect and cleanup resources."""
        if self.client_session:
            await self.client_session.close()
            self.client_session = None
        
        if self.connector:
            await self.connector.close()
            self.connector = None
        
        self._connected = False
        self._session = None


class StdioSecTransport(SecTransport):
    """Stdio transport with security testing capabilities."""
    
    def __init__(self, target: str, security_config: Optional[Dict[str, Any]] = None):
        super().__init__(target, security_config)
        self.process: Optional[asyncio.subprocess.Process] = None
    
    @asynccontextmanager
    async def connect_with_monitoring(self) -> AsyncContextManager[ClientSession]:
        """Create stdio connection with process monitoring."""
        try:
            # Parse command and args from target
            # Format: "command arg1 arg2" or just "command"
            parts = self.target.split()
            if not parts:
                raise TransportError("stdio", "Invalid command format")
            
            command = parts[0]
            args = parts[1:] if len(parts) > 1 else []
            
            # Create subprocess with security monitoring
            self.process = await asyncio.create_subprocess_exec(
                command,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            read, write = await stdio.stdio_client(self.process.stdin, self.process.stdout)
            
            mcp_session = ClientSession(read, write)
            self._session = mcp_session
            self._connected = True
            
            yield mcp_session
            
        except Exception as e:
            raise TransportError("stdio", f"Failed to connect: {str(e)}", e)
        finally:
            await self.disconnect()
    
    async def inject_malformed_request(self, payload: Dict[str, Any]) -> Any:
        """Inject malformed stdio requests for testing."""
        if not self.process or not self.process.stdin:
            raise TransportError("stdio", "Not connected")
        
        try:
            # Send malformed JSON to stdin
            malformed_json = json.dumps(payload) if payload else '{"malformed"'
            self.process.stdin.write((malformed_json + "\n").encode())
            await self.process.stdin.drain()
            
            # Try to read response (may timeout or error)
            try:
                stdout_data = await asyncio.wait_for(
                    self.process.stdout.readline(),
                    timeout=self.security_config.get("response_timeout", 5)
                )
                return {"stdout": stdout_data.decode().strip()}
            except asyncio.TimeoutError:
                return {"stdout": "", "timeout": True}
                
        except Exception as e:
            raise TransportError("stdio", f"Malformed request failed: {str(e)}", e)
    
    async def disconnect(self) -> None:
        """Disconnect and cleanup process."""
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
            finally:
                self.process = None
        
        self._connected = False
        self._session = None


class WSSecTransport(SecTransport):
    """WebSocket transport with security testing capabilities."""
    
    def __init__(self, target: str, security_config: Optional[Dict[str, Any]] = None):
        super().__init__(target, security_config)
        self.ws_session: Optional[aiohttp.ClientSession] = None
    
    @asynccontextmanager
    async def connect_with_monitoring(self) -> AsyncContextManager[ClientSession]:
        """Create WebSocket connection with monitoring."""
        try:
            # Configure WebSocket session
            timeout = aiohttp.ClientTimeout(
                total=self.security_config.get("total_timeout", 30),
                ws_connect=self.security_config.get("ws_connect_timeout", 10),
            )
            
            connector_kwargs = {}
            if self.security_config.get("disable_ssl_verify", False):
                connector_kwargs["verify_ssl"] = False
            
            connector = aiohttp.TCPConnector(**connector_kwargs)
            self.ws_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
            
            read, write = await websocket.websocket_client(self.target, self.ws_session)
            
            mcp_session = ClientSession(read, write)
            self._session = mcp_session
            self._connected = True
            
            yield mcp_session
            
        except Exception as e:
            raise TransportError("websocket", f"Failed to connect: {str(e)}", e)
        finally:
            await self.disconnect()
    
    async def inject_malformed_request(self, payload: Dict[str, Any]) -> Any:
        """Inject malformed WebSocket requests for testing."""
        if not self.ws_session:
            raise TransportError("websocket", "Not connected")
        
        try:
            async with self.ws_session.ws_connect(self.target) as ws:
                # Send malformed JSON
                malformed_json = json.dumps(payload) if payload else '{"malformed"'
                await ws.send_str(malformed_json)
                
                # Try to receive response
                try:
                    msg = await asyncio.wait_for(
                        ws.receive(),
                        timeout=self.security_config.get("response_timeout", 5)
                    )
                    return {
                        "type": msg.type.name,
                        "data": msg.data if hasattr(msg, 'data') else str(msg)
                    }
                except asyncio.TimeoutError:
                    return {"timeout": True}
                    
        except Exception as e:
            raise TransportError("websocket", f"Malformed request failed: {str(e)}", e)
    
    async def disconnect(self) -> None:
        """Disconnect WebSocket session."""
        if self.ws_session:
            await self.ws_session.close()
            self.ws_session = None
        
        self._connected = False
        self._session = None


class TransportFactory:
    """Factory for creating security-enhanced transports."""
    
    @staticmethod
    def create_transport(
        transport_type: str, 
        target: str, 
        security_config: Optional[Dict[str, Any]] = None
    ) -> SecTransport:
        """Create appropriate transport based on type."""
        transport_type = transport_type.lower()
        
        match transport_type:
            case "http" | "https" | "sse":
                return HTTPSecTransport(target, security_config)
            case "stdio":
                return StdioSecTransport(target, security_config)
            case "websocket" | "ws" | "wss":
                return WSSecTransport(target, security_config)
            case _:
                raise TransportError(
                    transport_type, 
                    f"Unsupported transport type: {transport_type}"
                )
    
    @staticmethod
    def get_supported_transports() -> list[str]:
        """Get list of supported transport types."""
        return ["http", "https", "sse", "stdio", "websocket", "ws", "wss"]