# mcpred - MCP Red Team Client

A Python command-line tool for security testing MCP (Model Context Protocol) servers. Designed for authorized security research and vulnerability assessment.

## What is mcpred?

mcpred enables security researchers and penetration testers to assess MCP server implementations for vulnerabilities through:

- **Server Discovery** - Enumerate capabilities, resources, tools, and attack surface
- **Authentication Testing** - Test OAuth flows, token handling, and privilege escalation
- **Protocol Fuzzing** - JSON-RPC malformation testing and schema validation bypass
- **Stress Testing** - DoS resistance, connection limits, and resource exhaustion testing
- **Security Reporting** - Professional reports in JSON, HTML, and text formats

## Quick Start

### Installation
```bash
git clone https://github.com/fear-ai/mcpred.git
cd mcpred
uv sync --dev
```

### Basic Usage
```bash
# Discover server capabilities
uv run python -m cli.main discover http://localhost:8080/mcp

# Run comprehensive security assessment
uv run python -m cli.main scan http://localhost:8080/mcp --all-tests

# Generate HTML security report
uv run python -m cli.main scan http://localhost:8080/mcp -o report.html --format html

# Initialize configuration file
uv run python -m cli.main init
```

### Example Output
```bash
$ uv run python -m cli.main discover http://localhost:8080/mcp

Discovering capabilities for http://localhost:8080/mcp using http transport...
✅ Server Info: test-server v1.0.0 (MCP 2024-11-05)
🔧 Tools: 3 discovered (echo, file_read, system_exec)
📄 Resources: 2 discovered (config files, logs)
💬 Prompts: 1 discovered (greeting)
⚠️  Security Issues: 2 potential concerns found
📊 Discovery report saved to discovery-report.json
```

## Key Features

### Security Testing Capabilities
- **Multi-transport support** - HTTP, WebSocket, stdio protocols
- **Vulnerability detection** - Information disclosure, authentication bypass, protocol violations
- **Risk assessment** - Automated severity scoring and classification
- **Safe testing** - Built-in limits and responsible disclosure practices

### Professional Tooling  
- **CLI interface** - Rich terminal output with progress indicators
- **Configuration management** - YAML/JSON config files with validation
- **Flexible reporting** - Multiple output formats for different audiences
- **Comprehensive logging** - Detailed audit trails for security assessments

### Architecture
- **Extends official MCP SDK** - Built on proven, protocol-compliant foundation
- **Async-first design** - Concurrent testing for efficiency
- **Modular security tests** - Extensible framework for custom assessments
- **Enterprise-ready** - Professional documentation and security practices

## Configuration

Create `.mcpred.yaml`:
```yaml
targets:
  - url: "http://localhost:8080/mcp"
    transport_type: "http"
    name: "local-server"

security:
  max_fuzz_requests: 100
  malformed_rate: 0.3
  enable_dangerous_tests: false

reporting:
  output_directory: "./reports"
  default_format: "json"

log_level: "INFO"
```

## Commands

- `discover [TARGET]` - Enumerate server capabilities and attack surface
- `scan [TARGET]` - Run comprehensive security assessment with all tests
- `init` - Generate sample configuration file
- `validate` - Validate configuration file syntax
- `version` - Show version information

## Security Warning

⚠️ **AUTHORIZED TESTING ONLY** - This tool is designed for security research and authorized penetration testing.

- Only test servers you own or have explicit permission to test
- Some tests may impact server performance or availability  
- Follow responsible disclosure practices for any vulnerabilities discovered
- Use `enable_dangerous_tests: false` in production environments

## Requirements

- **Python 3.11+** - Modern async support required
- **UV package manager** - Fast, reliable dependency management
- **MCP server access** - Target servers must be accessible for testing

## Project Status

- **89/109 tests passing** (82% success rate)
- **Production-ready core functionality** with comprehensive CLI
- **Active development** with regular updates and security improvements
- **Community contributions welcome** - See DESIGN.md for technical details

## Documentation

- **DESIGN.md** - Complete technical documentation and architecture details
- **GITHUB.md** - Repository management and security configuration guide  
- **TODO.md** - Development status and next steps for contributors

## License and Ethics

This project is focused on **defensive security** and authorized testing. It is designed to help improve MCP server security through responsible vulnerability research and disclosure.

## Support

- **Issues**: https://github.com/fear-ai/mcpred/issues
- **Discussions**: Use GitHub discussions for questions
- **Security**: Report vulnerabilities following responsible disclosure practices

Built for the security research community to strengthen MCP ecosystem security.