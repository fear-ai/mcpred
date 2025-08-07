# mcpred Core Implementation Architecture

## File Partitioning Strategy

Based on analysis of the official MCP Python SDK and mcp-use implementations, here's the proposed core architecture with tighter naming conventions:

### Complete Directory Structure (Fixed)
```
mcpred/
├── __init__.py                   # Package exports and version info
├── core/                         # Core implementation
│   ├── __init__.py
│   ├── client.py                # MCPTeamClient main class
│   ├── session.py               # Security-enhanced session wrapper  
│   ├── transports.py            # Transport implementations and factories
│   └── exceptions.py            # Custom security testing exceptions
├── security/                     # Security testing modules
│   ├── __init__.py
│   ├── discovery.py             # Server enumeration and capability detection
│   ├── auth_tests.py            # AuthTest - authentication bypass testing
│   ├── protocol_fuzzer.py       # JSON-RPC fuzzing and malformation
│   ├── stress_tests.py          # Performance and DoS testing
│   └── analyzers.py             # Vulnerability analysis and classification
├── reporting/                    # Report generation and formatting
│   ├── __init__.py
│   ├── formatters.py            # Output formatting (JSON, HTML, text)
│   ├── exporters.py             # Report export functionality
│   └── generators.py            # Report generation orchestration
├── config/                       # Configuration management
│   ├── __init__.py
│   ├── loader.py                # .mcpred config file loading
│   └── validation.py            # Configuration validation with Pydantic
└── cli/                          # Command-line interface
    ├── __init__.py
    ├── main.py                   # Main CLI entry point
    └── commands/                 # Individual command implementations
        ├── __init__.py
        └── discover.py           # Discovery command implementation
tests/                            # Unit and integration tests
├── __init__.py
├── conftest.py                   # Pytest configuration and fixtures
├── unit/                         # Unit tests
│   ├── test_client.py
│   ├── test_session.py
│   ├── test_transports.py
│   └── test_exceptions.py
└── integration/                  # Integration tests
    └── test_client_integration.py
DESIGN.md                        # Design document
IMPLEMENTATION.md                # Implementation details  
TODO.md                          # Project status and next steps
```

## Code Reuse Strategy

### 1. Extend Official MCP SDK (Primary Foundation)
```python
# mcpred/core/client.py
from mcp import ClientSession
from mcp.client.session import ElicitationFnT, SamplingFnT

class MCPTeamClient:
    """Security-focused MCP client extending official SDK functionality."""
    
    def __init__(self, target_url: str, transport_type: str = "http"):
        self.official_session: ClientSession | None = None
        self.transport_factory = TransportFactory()
        self.security_analyzer = SecurityAnalyzer()
        self.report_generator = ReportGenerator()
```

### 2. Reuse mcp-use Patterns (Transport Management)
```python
# mcpred/core/transports.py
# Adapt mcp-use's connector pattern for security testing
from abc import ABC, abstractmethod
from typing import Any, AsyncContextManager

class SecTransport(ABC):
    """Base class for security-enhanced MCP transports."""
    
    @abstractmethod
    async def connect_with_monitoring(self) -> AsyncContextManager[Any]:
        """Connect with security monitoring capabilities."""
    
    @abstractmethod
    async def inject_malformed_request(self, payload: dict) -> Any:
        """Inject malformed requests for fuzzing."""
```

## Library Dependencies

### Core MCP Libraries
```python
# From official MCP Python SDK
from mcp import ClientSession, types
from mcp.client.session import ElicitationFnT, SamplingFnT
from mcp.client import stdio, sse, websocket
from mcp.shared.exceptions import McpError
from mcp.shared.context import RequestContext
```

### Security Testing Libraries
```python
# HTTP testing and manipulation
import aiohttp
import requests
from urllib3 import disable_warnings

# JSON manipulation and fuzzing
import json
import jsonschema
from faker import Faker

# Cryptographic testing
from cryptography.fernet import Fernet
from jwt import decode, InvalidTokenError

# Network analysis
import socket
import ssl
```

### CLI and Configuration Libraries
```python
# CLI framework
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Configuration management
import pydantic
from pydantic import BaseSettings, validator
import yaml
import toml

# Async support
import asyncio
import anyio
from contextlib import asynccontextmanager
```

## Core Implementation Details

### 1. MCPTeamClient Class
```python
# mcpred/core/client.py
class MCPTeamClient:
    """Main client class for security testing MCP servers."""
    
    def __init__(
        self,
        target_url: str,
        transport_type: str = "http",
        security_config: SecurityConfig | None = None
    ):
        self.target = target_url
        self.transport = self._create_transport(transport_type)
        self.security_config = security_config or SecurityConfig()
        
        # Core components
        self.session_manager = SecSessionManager()
        self.discovery_engine = DiscoveryEngine()
        self.auth_test = AuthTest()
        self.protocol_fuzzer = ProtocolFuzzer()
        self.stress_tester = StressTester()
        
        # Reporting
        self.vuln_tracker = VulnTracker()
        self.report_generator = ReportGenerator()

    async def discover_server(self) -> ServerCapabilities:
        """Discover server capabilities and potential attack surface."""
        
    async def test_authentication(self) -> List[SecurityIssue]:
        """Test authentication mechanisms for vulnerabilities."""
        
    async def fuzz_protocol(self, 
                          request_count: int = 100,
                          malformed_rate: float = 0.3) -> List[ProtocolViolation]:
        """Perform protocol fuzzing with malformed requests."""
        
    async def stress_test(self) -> PerformanceMetrics:
        """Test server performance and DoS resistance."""
```

### 2. Security Session Wrapper
```python
# mcpred/core/session.py
class SecSessionManager:
    """Wrapper around MCP ClientSession with security monitoring."""
    
    def __init__(self, official_session: ClientSession):
        self.session = official_session
        self.request_logger = RequestLogger()
        self.vuln_detector = VulnDetector()
    
    async def monitored_request(self, method: str, params: dict) -> Any:
        """Make request with security monitoring and analysis."""
        # Log request details
        self.request_logger.log_outbound(method, params)
        
        try:
            response = await self.session.send_request(method, params)
            # Analyze response for vulnerabilities
            vulnerabilities = await self.vuln_detector.analyze_response(response)
            return response, vulnerabilities
        except McpError as e:
            # Analyze error for information disclosure
            error_analysis = await self.vuln_detector.analyze_error(e)
            raise SecurityAnalyzedError(e, error_analysis)
```

### 3. Transport Factory Pattern
```python
# mcpred/core/transports.py
class TransportFactory:
    """Factory for creating security-enhanced transports."""
    
    @staticmethod
    def create_transport(transport_type: str, security_config: SecurityConfig) -> SecTransport:
        match transport_type.lower():
            case "http" | "https":
                return HTTPSecTransport(security_config)
            case "stdio":
                return StdioSecTransport(security_config)
            case "websocket" | "ws":
                return WSSecTransport(security_config)
            case _:
                raise ValueError(f"Unsupported transport type: {transport_type}")

class HTTPSecTransport(SecTransport):
    """HTTP transport with security testing capabilities."""
    
    async def connect_with_monitoring(self) -> AsyncContextManager[ClientSession]:
        """Create HTTP connection with request/response monitoring."""
        
    async def inject_malformed_request(self, payload: dict) -> Any:
        """Inject malformed HTTP requests for testing."""

class StdioSecTransport(SecTransport):
    """Stdio transport with security testing capabilities."""
    pass

class WSSecTransport(SecTransport):
    """WebSocket transport with security testing capabilities."""
    pass
```

### 4. Security Testing Modules
```python
# mcpred/security/discovery.py
class DiscoveryEngine:
    """Server discovery and enumeration engine."""
    
    async def enumerate_capabilities(self, session: ClientSession) -> ServerCapabilities:
        """Enumerate server capabilities, resources, tools, prompts."""
        
    async def detect_transport_methods(self, target: str) -> List[TransportMethod]:
        """Detect available transport methods (HTTP, WebSocket, etc.)."""
        
    async def fingerprint_server(self, session: ClientSession) -> ServerFingerprint:
        """Fingerprint server implementation and version."""

# mcpred/security/auth_tests.py
class AuthTest:
    """Authentication bypass and token manipulation testing."""
    
    async def test_oauth_bypass(self, session: ClientSession) -> List[SecurityIssue]:
        """Test OAuth 2.1 implementation for bypass vulnerabilities."""
        
    async def test_token_manipulation(self, session: ClientSession) -> List[SecurityIssue]:
        """Test JWT and token handling for vulnerabilities."""
        
    async def test_privilege_escalation(self, session: ClientSession) -> List[SecurityIssue]:
        """Test for privilege escalation vulnerabilities."""

# mcpred/security/protocol_fuzzer.py
class ProtocolFuzzer:
    """JSON-RPC protocol fuzzing and malformation testing."""
    
    async def fuzz_json_rpc(self, session: ClientSession, fuzz_config: FuzzConfig) -> List[ProtocolViolation]:
        """Fuzz JSON-RPC requests with malformed data."""
        
    async def test_schema_violations(self, session: ClientSession) -> List[ProtocolViolation]:
        """Test schema validation bypass attempts."""

# mcpred/security/stress_tests.py
class StressTester:
    """Performance and DoS resistance testing."""
    
    async def test_connection_limits(self, target: str) -> PerformanceMetrics:
        """Test server connection handling limits."""
        
    async def test_resource_exhaustion(self, session: ClientSession) -> PerformanceMetrics:
        """Test server resource exhaustion resistance."""
```

## Tighter Naming Convention Summary

### Class Names
- `RedTeamMCPClient` → `MCPTeamClient`
- `AuthenticationTester` → `AuthTest`
- `HTTPSecurityTransport` → `HTTPSecTransport`
- `WebSocketSecurityTransport` → `WSSecTransport`
- `StdioSecurityTransport` → `StdioSecTransport`
- `SecurityTransport` → `SecTransport`
- `SecuritySessionManager` → `SecSessionManager`
- `VulnerabilityTracker` → `VulnTracker`
- `VulnerabilityDetector` → `VulnDetector`

### Module Responsibilities

#### Core Modules
- **`client.py`**: Main `MCPTeamClient` orchestrator class
- **`session.py`**: Enhanced session management with `SecSessionManager`
- **`transports.py`**: Transport implementations (`HTTPSecTransport`, `WSSecTransport`, etc.)
- **`exceptions.py`**: Custom exceptions for security testing scenarios

#### Security Modules
- **`discovery.py`**: Server enumeration, capability detection, fingerprinting
- **`auth_tests.py`**: `AuthTest` class for authentication bypass, token manipulation
- **`protocol_fuzzer.py`**: JSON-RPC fuzzing, schema validation bypass
- **`stress_tests.py`**: Performance testing, DoS resistance, resource exhaustion
- **`analyzers.py`**: Vulnerability classification, risk assessment, impact analysis

#### Supporting Modules
- **`reporting/`**: Output formatting, report generation, export functionality
- **`config/`**: Configuration file loading, validation, default settings
- **`cli/`**: Command-line interface, argument parsing, command dispatch

## Code Reuse Benefits

1. **Official MCP SDK**: Ensures protocol compliance and handles transport complexity
2. **mcp-use Patterns**: Proven async patterns and configuration management
3. **Standard Libraries**: Leverages Python security ecosystem (cryptography, requests, etc.)
4. **Click Framework**: Mature CLI development with rich formatting support

This tighter naming convention maintains readability while reducing verbosity, making the codebase more concise and easier to work with during development and debugging.