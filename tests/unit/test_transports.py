"""
Unit tests for transport implementations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from mcpred.core.transports import (
    TransportFactory, 
    SecTransport, 
    HTTPSecTransport, 
    StdioSecTransport, 
    WSSecTransport
)
from mcpred.core.exceptions import TransportError


class TestTransportFactory:
    """Test TransportFactory class."""
    
    def test_create_http_transport(self):
        """Test creating HTTP transport."""
        transport = TransportFactory.create_transport("http", "http://test:8080")
        
        assert isinstance(transport, HTTPSecTransport)
        assert transport.target == "http://test:8080"
    
    def test_create_https_transport(self):
        """Test creating HTTPS transport."""
        transport = TransportFactory.create_transport("https", "https://test:8080")
        
        assert isinstance(transport, HTTPSecTransport)
        assert transport.target == "https://test:8080"
    
    def test_create_stdio_transport(self):
        """Test creating stdio transport."""
        transport = TransportFactory.create_transport("stdio", "python server.py")
        
        assert isinstance(transport, StdioSecTransport)
        assert transport.target == "python server.py"
    
    def test_create_websocket_transport(self):
        """Test creating WebSocket transport."""
        transport = TransportFactory.create_transport("websocket", "ws://test:8080")
        
        assert isinstance(transport, WSSecTransport)
        assert transport.target == "ws://test:8080"
    
    def test_create_ws_transport(self):
        """Test creating WebSocket transport with 'ws' type."""
        transport = TransportFactory.create_transport("ws", "ws://test:8080")
        
        assert isinstance(transport, WSSecTransport)
    
    def test_unsupported_transport(self):
        """Test creating unsupported transport type."""
        with pytest.raises(TransportError) as exc_info:
            TransportFactory.create_transport("ftp", "ftp://test")
        
        assert "Unsupported transport type: ftp" in str(exc_info.value)
    
    def test_get_supported_transports(self):
        """Test getting list of supported transports."""
        supported = TransportFactory.get_supported_transports()
        
        assert "http" in supported
        assert "https" in supported
        assert "stdio" in supported
        assert "websocket" in supported
        assert "ws" in supported
        assert "wss" in supported
    
    def test_case_insensitive_transport_type(self):
        """Test transport type is case insensitive."""
        transport1 = TransportFactory.create_transport("HTTP", "http://test")
        transport2 = TransportFactory.create_transport("WebSocket", "ws://test")
        
        assert isinstance(transport1, HTTPSecTransport)
        assert isinstance(transport2, WSSecTransport)


class TestHTTPSecTransport:
    """Test HTTPSecTransport class."""
    
    def test_initialization(self):
        """Test HTTP transport initialization."""
        config = {"connection_limit": 50, "disable_ssl_verify": True}
        transport = HTTPSecTransport("http://test:8080", config)
        
        assert transport.target == "http://test:8080"
        assert transport.security_config == config
        assert not transport.connected
        assert transport.connector is None
        assert transport.client_session is None
    
    def test_connected_property(self):
        """Test connected property."""
        transport = HTTPSecTransport("http://test")
        
        assert not transport.connected
        
        transport._connected = True
        assert transport.connected
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_success(self):
        """Test successful HTTP connection."""
        transport = HTTPSecTransport("http://test:8080")
        
        with patch('mcpred.core.transports.sse.sse_client') as mock_sse:
            with patch('aiohttp.ClientSession') as mock_session_class:
                with patch('aiohttp.TCPConnector') as mock_connector_class:
                    # Mock the sse client
                    mock_read = AsyncMock()
                    mock_write = AsyncMock()
                    mock_sse.return_value = (mock_read, mock_write)
                    
                    # Mock aiohttp components
                    mock_connector = MagicMock()
                    mock_connector_class.return_value = mock_connector
                    
                    mock_session = MagicMock()
                    mock_session_class.return_value = mock_session
                    
                    async with transport.connect_with_monitoring() as session:
                        assert transport.connected
                        assert transport.connector == mock_connector
                        assert transport.client_session == mock_session
                        
                        # Verify sse_client was called with correct params
                        mock_sse.assert_called_once_with("http://test:8080", mock_session)
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_error(self):
        """Test HTTP connection error."""
        transport = HTTPSecTransport("http://test:8080")
        
        with patch('mcpred.core.transports.sse.sse_client') as mock_sse:
            mock_sse.side_effect = Exception("Connection failed")
            
            with pytest.raises(TransportError) as exc_info:
                async with transport.connect_with_monitoring():
                    pass
            
            assert "http" in str(exc_info.value)
            assert "Connection failed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_success(self):
        """Test successful malformed request injection."""
        transport = HTTPSecTransport("http://test:8080")
        
        # Mock client session
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.text.return_value = '{"error": "Bad Request"}'
        
        mock_session = AsyncMock()
        mock_session.post.return_value.__aenter__.return_value = mock_response
        
        transport.client_session = mock_session
        
        payload = {"malformed": "request"}
        result = await transport.inject_malformed_request(payload)
        
        assert result["status"] == 400
        assert result["headers"]["Content-Type"] == "application/json"
        assert "error" in result["text"]
        
        # Verify post was called with malformed JSON
        mock_session.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_not_connected(self):
        """Test malformed request when not connected."""
        transport = HTTPSecTransport("http://test:8080")
        
        with pytest.raises(TransportError) as exc_info:
            await transport.inject_malformed_request({"test": "payload"})
        
        assert "Not connected" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_error(self):
        """Test malformed request injection error."""
        transport = HTTPSecTransport("http://test:8080")
        
        mock_session = AsyncMock()
        mock_session.post.side_effect = Exception("Request failed")
        transport.client_session = mock_session
        
        with pytest.raises(TransportError) as exc_info:
            await transport.inject_malformed_request({})
        
        assert "Malformed request failed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test HTTP transport disconnect."""
        transport = HTTPSecTransport("http://test:8080")
        
        # Mock connected state
        mock_session = AsyncMock()
        mock_connector = AsyncMock()
        transport.client_session = mock_session
        transport.connector = mock_connector
        transport._connected = True
        
        await transport.disconnect()
        
        assert not transport.connected
        assert transport.client_session is None
        assert transport.connector is None
        
        # Verify cleanup methods were called
        mock_session.close.assert_called_once()
        mock_connector.close.assert_called_once()
    
    def test_security_config_integration(self):
        """Test security configuration integration."""
        config = {
            "connection_limit": 25,
            "per_host_limit": 10,
            "total_timeout": 15,
            "disable_ssl_verify": True
        }
        
        transport = HTTPSecTransport("https://test:8080", config)
        
        assert transport.security_config["connection_limit"] == 25
        assert transport.security_config["disable_ssl_verify"] is True


class TestStdioSecTransport:
    """Test StdioSecTransport class."""
    
    def test_initialization(self):
        """Test stdio transport initialization."""
        transport = StdioSecTransport("python server.py", {"timeout": 10})
        
        assert transport.target == "python server.py"
        assert transport.security_config["timeout"] == 10
        assert transport.process is None
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_success(self):
        """Test successful stdio connection."""
        transport = StdioSecTransport("python server.py")
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            with patch('mcpred.core.transports.stdio.stdio_client') as mock_stdio:
                # Mock subprocess
                mock_process = AsyncMock()
                mock_process.stdin = AsyncMock()
                mock_process.stdout = AsyncMock()
                mock_subprocess.return_value = mock_process
                
                # Mock stdio client
                mock_read = AsyncMock()
                mock_write = AsyncMock()
                mock_stdio.return_value = (mock_read, mock_write)
                
                async with transport.connect_with_monitoring() as session:
                    assert transport.connected
                    assert transport.process == mock_process
                    
                    # Verify subprocess was created with correct command
                    mock_subprocess.assert_called_once_with(
                        "python", "server.py",
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_invalid_command(self):
        """Test stdio connection with invalid command."""
        transport = StdioSecTransport("")  # Empty command
        
        with pytest.raises(TransportError) as exc_info:
            async with transport.connect_with_monitoring():
                pass
        
        assert "Invalid command format" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_subprocess_error(self):
        """Test stdio connection subprocess error."""
        transport = StdioSecTransport("invalid_command")
        
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_subprocess.side_effect = Exception("Process creation failed")
            
            with pytest.raises(TransportError) as exc_info:
                async with transport.connect_with_monitoring():
                    pass
            
            assert "stdio" in str(exc_info.value)
            assert "Process creation failed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_success(self):
        """Test successful malformed request injection."""
        transport = StdioSecTransport("python server.py")
        
        # Mock process with stdin/stdout
        mock_stdin = AsyncMock()
        mock_stdout = AsyncMock()
        mock_stdout.readline.return_value = b'{"response": "data"}\n'
        
        mock_process = MagicMock()
        mock_process.stdin = mock_stdin
        mock_process.stdout = mock_stdout
        
        transport.process = mock_process
        
        payload = {"malformed": "json"}
        result = await transport.inject_malformed_request(payload)
        
        assert "stdout" in result
        assert result["stdout"] == '{"response": "data"}'
        
        # Verify data was written to stdin
        mock_stdin.write.assert_called_once()
        mock_stdin.drain.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_timeout(self):
        """Test malformed request with timeout."""
        transport = StdioSecTransport("python server.py", {"response_timeout": 1})
        
        # Mock process that times out
        mock_stdin = AsyncMock()
        mock_stdout = AsyncMock()
        mock_stdout.readline.side_effect = asyncio.TimeoutError()
        
        mock_process = MagicMock()
        mock_process.stdin = mock_stdin
        mock_process.stdout = mock_stdout
        
        transport.process = mock_process
        
        result = await transport.inject_malformed_request({})
        
        assert result["timeout"] is True
        assert result["stdout"] == ""
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_not_connected(self):
        """Test malformed request when not connected."""
        transport = StdioSecTransport("python server.py")
        
        with pytest.raises(TransportError) as exc_info:
            await transport.inject_malformed_request({})
        
        assert "Not connected" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test stdio transport disconnect."""
        transport = StdioSecTransport("python server.py")
        
        # Mock process
        mock_process = AsyncMock()
        mock_process.wait.return_value = 0
        transport.process = mock_process
        transport._connected = True
        
        await transport.disconnect()
        
        assert not transport.connected
        assert transport.process is None
        
        # Verify process cleanup
        mock_process.terminate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect_force_kill(self):
        """Test stdio disconnect with force kill."""
        transport = StdioSecTransport("python server.py")
        
        # Mock process that doesn't terminate gracefully
        mock_process = AsyncMock()
        mock_process.wait.side_effect = asyncio.TimeoutError()
        transport.process = mock_process
        transport._connected = True
        
        await transport.disconnect()
        
        # Should call kill after terminate timeout
        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()
    
    def test_command_parsing(self):
        """Test command and args parsing."""
        # Test simple command
        transport1 = StdioSecTransport("python")
        # Test command with args
        transport2 = StdioSecTransport("python server.py --debug")
        
        # Command parsing happens in connect_with_monitoring
        # We test it indirectly through the target storage
        assert transport1.target == "python"
        assert transport2.target == "python server.py --debug"


class TestWSSecTransport:
    """Test WSSecTransport class."""
    
    def test_initialization(self):
        """Test WebSocket transport initialization."""
        config = {"ws_connect_timeout": 5, "disable_ssl_verify": True}
        transport = WSSecTransport("ws://test:8080", config)
        
        assert transport.target == "ws://test:8080"
        assert transport.security_config == config
        assert transport.ws_session is None
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_success(self):
        """Test successful WebSocket connection."""
        transport = WSSecTransport("ws://test:8080")
        
        with patch('mcpred.core.transports.websocket.websocket_client') as mock_ws:
            with patch('aiohttp.ClientSession') as mock_session_class:
                # Mock websocket client
                mock_read = AsyncMock()
                mock_write = AsyncMock()
                mock_ws.return_value = (mock_read, mock_write)
                
                # Mock aiohttp session
                mock_session = MagicMock()
                mock_session_class.return_value = mock_session
                
                async with transport.connect_with_monitoring() as session:
                    assert transport.connected
                    assert transport.ws_session == mock_session
                    
                    # Verify websocket_client was called
                    mock_ws.assert_called_once_with("ws://test:8080", mock_session)
    
    @pytest.mark.asyncio
    async def test_connect_with_monitoring_error(self):
        """Test WebSocket connection error."""
        transport = WSSecTransport("ws://test:8080")
        
        with patch('mcpred.core.transports.websocket.websocket_client') as mock_ws:
            mock_ws.side_effect = Exception("WebSocket connection failed")
            
            with pytest.raises(TransportError) as exc_info:
                async with transport.connect_with_monitoring():
                    pass
            
            assert "websocket" in str(exc_info.value)
            assert "WebSocket connection failed" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_success(self):
        """Test successful WebSocket malformed request."""
        transport = WSSecTransport("ws://test:8080")
        
        # Mock WebSocket connection
        mock_ws = AsyncMock()
        mock_msg = MagicMock()
        mock_msg.type.name = "TEXT"
        mock_msg.data = '{"response": "test"}'
        mock_ws.receive.return_value = mock_msg
        
        mock_session = AsyncMock()
        mock_session.ws_connect.return_value.__aenter__.return_value = mock_ws
        
        transport.ws_session = mock_session
        
        payload = {"malformed": "ws_request"}
        result = await transport.inject_malformed_request(payload)
        
        assert result["type"] == "TEXT"
        assert "response" in result["data"]
        
        # Verify message was sent
        mock_ws.send_str.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_timeout(self):
        """Test WebSocket malformed request with timeout."""
        transport = WSSecTransport("ws://test:8080", {"response_timeout": 1})
        
        # Mock WebSocket that times out
        mock_ws = AsyncMock()
        mock_ws.receive.side_effect = asyncio.TimeoutError()
        
        mock_session = AsyncMock()
        mock_session.ws_connect.return_value.__aenter__.return_value = mock_ws
        
        transport.ws_session = mock_session
        
        result = await transport.inject_malformed_request({})
        
        assert result["timeout"] is True
    
    @pytest.mark.asyncio
    async def test_inject_malformed_request_not_connected(self):
        """Test WebSocket malformed request when not connected."""
        transport = WSSecTransport("ws://test:8080")
        
        with pytest.raises(TransportError) as exc_info:
            await transport.inject_malformed_request({})
        
        assert "Not connected" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test WebSocket transport disconnect."""
        transport = WSSecTransport("ws://test:8080")
        
        # Mock session
        mock_session = AsyncMock()
        transport.ws_session = mock_session
        transport._connected = True
        
        await transport.disconnect()
        
        assert not transport.connected
        assert transport.ws_session is None
        
        # Verify session cleanup
        mock_session.close.assert_called_once()
    
    def test_ssl_configuration(self):
        """Test SSL configuration for WebSocket transport."""
        config = {"disable_ssl_verify": True, "ws_connect_timeout": 15}
        transport = WSSecTransport("wss://secure:8080", config)
        
        assert transport.security_config["disable_ssl_verify"] is True
        assert transport.security_config["ws_connect_timeout"] == 15