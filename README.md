# mcpred - MCP Red Team Client

A Python command-line tool for security testing MCP (Model Context Protocol) servers.
Designed for authorized security research and vulnerability assessment.

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
# Discover server capabilities (short alias: dis)
mcpred discover https://api.example.com/mcp

# Run comprehensive security assessment (short alias: sc)
mcpred scan https://api.example.com/mcp

# Generate HTML security report
mcpred scan https://api.example.com/mcp -o report.html --fmt html
```

### Example Output
```bash
$ mcpred dis https://api.example.com/mcp

Discovering capabilities for https://api.example.com/mcp using https transport...

Server Capabilities:
  Tools: 5
  Resources: 3
  Prompts: 2
  Security Issues: 1

Discovery completed successfully
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

## Commands

### Core Commands

All commands have short aliases and support extensive options.

#### `discover` / `dis` - Server Discovery
Enumerate server capabilities and potential attack surface.

```bash
mcpred discover <TARGET> [OPTIONS]
mcpred dis <TARGET> [OPTIONS]
```

**Options:**
- `--transport, --tran, -t` - Transport type (http, https, stdio, websocket, ws, wss) [default: https]
- `--output, -o` - Output file path
- `--format, --fmt` - Output format (json, html, text) [default: text]  
- `--timeout, --time` - Operation timeout in seconds

**Examples:**
```bash
mcpred dis https://api.example.com/mcp
mcpred discover https://api.example.com/mcp --tran https --fmt html -o discovery.html
```

#### `scan` / `sc` - Security Assessment
Run comprehensive security testing with configurable test selection.

```bash
mcpred scan <TARGET> [OPTIONS]
mcpred sc <TARGET> [OPTIONS]
```

**Options:**
- `--transport, --tran, -t` - Transport type [default: https]
- `--output, -o` - Output file path
- `--format, --fmt` - Output format [default: text]
- `--auth/--noauth` - Enable/disable authentication tests [default: enabled]
- `--discovery/--nodiscovery, --dis/--nodis` - Enable/disable server discovery [default: enabled]
- `--fuzz/--nofuzz` - Enable/disable protocol fuzzing [default: enabled]
- `--stress/--nostress` - Enable/disable stress testing [default: enabled]

**Examples:**
```bash
mcpred sc https://api.example.com/mcp
mcpred scan https://api.example.com/mcp --nofuzz --nostress --fmt html -o report.html
mcpred sc https://api.example.com/mcp --noauth --tran websocket
```

#### `conf` - Configuration Management
Create sample configuration file or validate existing configuration.

```bash
mcpred conf [FILENAME]
```

**Behavior:**
- Without filename: Creates sample `.mcpred` configuration file
- With filename: Validates the specified configuration file

**Examples:**
```bash
mcpred conf                      # Create sample .mcpred
mcpred conf myconfig.mcpred      # Validate myconfig.mcpred
```

#### `run` - Test Definition Execution
Execute test definitions from .red files.

```bash
mcpred run <RED_FILE>
mcpred <RED_FILE>  # Direct execution
```

**Examples:**
```bash
mcpred run bigtest.red
mcpred quicktest.red  # Direct execution
```

### Common Options
- `--config, --conf, -c` - Configuration file path
- `--verbose, --verb, -v` - Enable verbose output
- `--log-level, --loglev` - Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) [default: INFO]
- `--log-file, --logfile` - Log file path
- `--version` - Show version information
- `--help` - Show help message

## Configuration

### Configuration File (.mcpred)

Create `.mcpred` configuration file:
```yaml
# Security testing configuration
security:
  max_fuzz_requests: 100
  malformed_rate: 0.3
  enable_dangerous: false
  max_connections: 50
  stress_duration: 60
  request_rate: 10

# Transport configuration
transport:
  total_timeout: 30.0
  connect_timeout: 10.0
  response_timeout: 5.0
  disable_ssl_verify: false
  connection_limit: 100
  per_host_limit: 30

# Reporting configuration
reporting:
  output_dir: "./reports"
  default_fmt: "text"
  include_raw: false

# Logging
log_level: "INFO"
```

### Test Definition Files

Create reusable test configurations with `.red` extension:

```yaml
# quicktest.red - Basic discovery only
target: "https://dev.example.com/mcp"
transport: "https"
format: "text"

# Test selection
auth: false
discovery: true
fuzz: false
stress: false
```

```yaml
# bigtest.red - Comprehensive security assessment
target: "https://prod.example.com/mcp"
transport: "https"
output: "comprehensive-report.html"
format: "html"

# All tests enabled
auth: true
discovery: true
fuzz: true
stress: true

# Aggressive security parameters
security:
  max_fuzz_requests: 500
  malformed_rate: 0.4
  enable_dangerous: true
  stress_duration: 120

# Extended timeouts for thorough testing
transport_config:
  total_timeout: 60.0
  connect_timeout: 20.0
```

## Usage Examples

### Simple Discovery
```bash
# Quick server enumeration
mcpred dis https://api.example.com/mcp

# Discovery with custom transport and HTML output
mcpred discover wss://ws.example.com/mcp --tran websocket --fmt html -o discovery.html

# Stdio server discovery
mcpred dis "python -m server" --tran stdio --fmt json
```

### Comprehensive Security Assessment
```bash
# Full security scan with all tests
mcpred sc https://api.example.com/mcp -o full-report.html --fmt html

# Targeted testing (skip resource-intensive tests)
mcpred scan https://api.example.com/mcp --nofuzz --nostress

# Authentication-focused testing
mcpred sc https://api.example.com/mcp --nodis --nofuzz --nostress --auth
```

### Configuration-Based Testing
```bash
# Create and customize configuration
mcpred conf # Creates example.red
# Edit with your settings
mcpred conf --conf conf.red https://prod.example.com/mcp

# Validate configuration before testing
mcpred sc production.mcpred
```

### Test Definition Workflows
```bash
# Create test definition for repeated use
cat > daily-check.red << EOF
target: "https://api.example.com/mcp"
format: "html"
output: "daily-security-check.html"
auth: true
discovery: true
fuzz: false
stress: false
EOF

# Run tests directly from definitions
mcpred daily.red
mcpred quicktest.red    # Basic discovery
mcpred bigtest.red      # Comprehensive assessment
```

### Advanced Usage
```bash
# Verbose logging for debugging
mcpred sc https://api.example.com/mcp --loglev DEBUG --logfile mcpred.log

# Custom timeout for slow servers
mcpred dis https://slow-api.example.com/mcp --time 60

# Multiple output formats
mcpred sc https://api.example.com/mcp -o report.json --fmt json
# Automatically generates report.html as well

# Batch testing with different configurations
for config in dev.mcpred staging.mcpred prod.mcpred; do
    mcpred sc --conf $config -o "report-$(basename $config .mcpred).html"
done
```

## Requirements

- **Python 3.12+** - Modern async support required
- **UV package manager** - Fast, reliable dependency management
- **MCP server access** - Target servers must be accessible for testing

## Documentation

- **DESIGN.md** - Complete technical documentation and architecture details
- **GITHUB.md** - Repository management and security configuration guide  
- **TODO.md** - Development status and next steps for contributors

## Security Warning

⚠️ **AUTHORIZED TESTING ONLY** - This tool is designed for security research and authorized penetration testing.

- Only test servers you own or have explicit permission to test
- Some tests may impact server performance or availability  
- Follow responsible disclosure practices for any vulnerabilities discovered
- Use `enable_dangerous: false` in production environments

## License

This project is focused on **defensive security** and authorized testing.
It is designed to help improve MCP server security through responsible vulnerability research and disclosure.

## Support

- **Issues**: https://github.com/fear-ai/mcpred/issues
- **Security**: Report vulnerabilities to respective vendors following responsible disclosure practices
