# mcpred - MCP Red Team Client Design Document

## Project Overview

**Project Title:** mcpred  
**CLI Command:** `mcpred`  
**Configuration File:** `.mcpred`  
**Type:** Python-based command line MCP client for red teaming and security testing  
**Purpose:** Exercise and test remote MCP servers to identify vulnerabilities and weaknesses

## Local Repository References

Local copies of reviewed implementations:
- `/Users/walter/Work/Github/typescript-sdk` - Official MCP TypeScript SDK
- `/Users/walter/Work/Github/python-sdk` - Official MCP Python SDK  
- `/Users/walter/Work/Github/example-remote-client` - Official example client
- `/Users/walter/Work/Github/mcp-use` - Independent implementation

## Architecture Analysis

### Existing MCP Client Implementations Review

#### 1. Official MCP Python SDK
- **Language:** Python
- **Architecture:** Async-first design with session-based client and protocol negotiation
- **Strengths:** Production-ready, strong type safety, comprehensive protocol support
- **Weaknesses:** Server-focused, limited CLI examples, complex for simple use cases

#### 2. Official MCP TypeScript SDK  
- **Language:** TypeScript
- **Architecture:** Generic client with flexible transport support, event-driven communication
- **Strengths:** Excellent TypeScript integration, strong security (OAuth 2.1), multiple transports
- **Weaknesses:** Complex setup, web-focused, less suitable for CLI applications

#### 3. Example Remote Client (Official)
- **Language:** TypeScript/React
- **Architecture:** React-based web application with context provider pattern
- **Strengths:** Modern UI patterns, comprehensive feature demonstration
- **Weaknesses:** Web-only, not suitable for CLI, complex for automation

#### 4. mcp-use (Independent)
- **Language:** Python  
- **Architecture:** Agent-based with LangChain integration, multi-server support
- **Strengths:** Simple API, excellent LLM integration, flexible configuration
- **Weaknesses:** Limited protocol compliance details, LangChain dependency

## Technology Selection

### Language Decision: Python

**Rationale:**
- **Security Ecosystem:** Superior tools (`requests`, `aiohttp`, `pwntools`, `scapy`, `cryptography`)
- **CLI Frameworks:** Mature options (`click`, `typer`, `rich` for formatting)
- **Async Support:** Excellent async/await for concurrent testing
- **Red Team Integration:** Better compatibility with existing Python security tools

**TypeScript Rejected Because:**
- Limited security tooling ecosystem
- CLI tools less mature than Python equivalents
- More complex async patterns for testing scenarios

## Requirements and Specifications

### Core Requirements

**Primary Goals:**
- Exercise MCP servers to identify vulnerabilities and weaknesses
- Perform security testing and protocol compliance validation  
- Support red team operations with automated testing capabilities

**Essential Features:**
1. **Multi-transport Support** - stdio, HTTP, SSE, WebSocket
2. **Protocol Fuzzing** - Test malformed requests and edge cases
3. **Authentication Testing** - Test bypass attempts and weak implementations
4. **Resource Enumeration** - Discover and catalog server capabilities
5. **Stress Testing** - Performance limits and DoS resilience
6. **Logging & Reporting** - Comprehensive audit trails

### Technical Architecture

```
mcpred/
├── mcpred/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── client.py          # Base MCP client with security extensions
│   │   ├── transports.py      # Transport implementations
│   │   └── protocol.py        # Protocol handling with fuzzing
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── auth_tests.py      # Authentication bypass tests
│   │   ├── fuzzing.py         # Protocol fuzzing tests
│   │   └── stress_tests.py    # Performance/DoS tests
│   ├── reports/
│   │   ├── __init__.py
│   │   └── formatters.py      # Output formatting (JSON, HTML, txt)
│   └── cli.py                 # Main command interface
├── tests/                     # Unit and integration tests
├── docs/                      # Documentation
├── pyproject.toml            # Project configuration
└── README.md
```

## Core Design Patterns

### Base Security-Focused MCP Client
```python
class MCPTeamClient:
    def __init__(self, target_url, transport_type="http"):
        self.session = MCPSession()
        self.transport = self._create_transport(transport_type)
        self.fuzzer = ProtocolFuzzer()
        self.reporter = SecurityReporter()
    
    async def discover(self) -> ServerCapabilities
    async def test_authentication(self) -> List[SecurityIssue]  
    async def fuzz_protocol(self) -> List[ProtocolViolation]
    async def stress_test(self) -> PerformanceMetrics
```

### Command Line Interface
```bash
# Discovery and enumeration
mcpred discover --target http://server:8080 --output json

# Authentication testing  
mcpred auth --target server --test-bypass --test-weak-tokens

# Protocol fuzzing
mcpred fuzz --target server --requests 1000 --malformed-rate 0.3

# Comprehensive scan
mcpred scan --target server --all-tests --report-format html

# Configuration file support
mcpred --config .mcpred scan --target-list servers.yaml
```

## Security Test Modules

### 1. Discovery Module
- Server enumeration and capability mapping
- Transport detection and analysis
- Resource and tool inventory

### 2. Authentication Testing
- OAuth bypass attempts
- Token manipulation and validation
- Privilege escalation testing
- Session management vulnerabilities

### 3. Protocol Fuzzing  
- Malformed JSON-RPC requests
- Invalid schema testing
- Edge case parameter testing
- Protocol compliance validation

### 4. Stress Testing
- Connection limit testing
- Resource exhaustion attempts
- DoS resistance evaluation
- Performance degradation analysis

### 5. Data Extraction
- Information disclosure testing
- Sensitive data leakage detection
- Error message analysis
- Metadata extraction

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
- **MVP Client:** Basic MCP client with HTTP/stdio transport
- **Discovery:** Server enumeration and capability detection  
- **CLI Framework:** Command structure with Click/typer
- **Basic Reporting:** JSON output format

### Phase 2: Security Testing (Week 3-4)
- **Authentication Tests:** OAuth bypass, token manipulation
- **Protocol Fuzzing:** JSON-RPC malformation testing
- **Input Validation:** Parameter injection and boundary testing
- **Error Analysis:** Information disclosure via error messages

### Phase 3: Advanced Features (Week 5-6)
- **Stress Testing:** Connection limits and DoS resistance
- **Multi-target:** Concurrent testing of multiple servers
- **Report Generation:** HTML reports with vulnerability details
- **Configuration:** `.mcpred` config file support with YAML/JSON test suites

### Phase 4: Enhancement (Week 7+)
- **Plugin System:** Custom test modules
- **Integration:** CI/CD pipeline integration
- **Documentation:** Usage guides and test methodology

## Key Implementation Insights

### From Official MCP Python SDK
- **Critical Pattern:** Session-based client with proper initialization flow
- **Transport Abstraction:** Clean separation between protocol and transport
- **Error Handling:** Structured exceptions with detailed context
- **Validation:** Pydantic models for request/response validation

### From Example Remote Client
- **Multi-server Support:** Architecture for testing multiple targets
- **OAuth Implementation:** Reference for authentication testing
- **Streaming Support:** Real-time response handling

### From mcp-use
- **Simple CLI Pattern:** Configuration-driven approach
- **LLM Integration:** For intelligent test case generation
- **Connector Abstraction:** Pluggable transport mechanisms

## Dependencies

### Core Dependencies
- `mcp` - Official MCP Python SDK (foundation)
- `click` or `typer` - CLI framework
- `aiohttp` - HTTP client for async operations
- `websockets` - WebSocket transport support
- `pydantic` - Data validation and settings
- `rich` - Terminal formatting and progress bars

### Security Testing Dependencies
- `requests` - HTTP testing and manipulation
- `cryptography` - Authentication and token testing
- `pytest` - Testing framework
- `pytest-asyncio` - Async test support

### Optional Dependencies
- `pwntools` - Advanced protocol exploitation
- `scapy` - Network packet manipulation
- `jinja2` - HTML report templating

## Design Decisions Summary

1. **Python over TypeScript:** Superior security tooling ecosystem and CLI frameworks
2. **Extend Official SDK:** Build on proven MCP protocol implementation
3. **Modular Architecture:** Pluggable transports and test modules
4. **CLI-First Design:** Command-line interface similar to nmap/sqlmap
5. **Async-First:** Leverage Python's async/await for concurrent testing
6. **Security-Focused:** Specialized testing capabilities not found in existing clients
7. **Comprehensive Reporting:** Multiple output formats for different use cases

## Next Immediate Steps

1. Set up project structure with proper dependency management
2. Implement basic MCP client using official Python SDK as foundation
3. Create CLI interface with discovery command as first feature
4. Add transport abstraction for HTTP/stdio/WebSocket support
5. Begin with minimal viable client for server discovery and capability enumeration