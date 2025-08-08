# mcpred - MCP Red Team Client

A Python command-line tool for security testing MCP (Model Context Protocol) servers.
Designed for authorized security research and vulnerability assessment.

- **Server Discovery** - Enumerate capabilities, resources, tools, and suggest an attack surface
- **Authentication Testing** - Test OAuth flows, token handling, and privilege escalation
- **Protocol Fuzzing** - JSON-RPC malformation testing and schema validation bypass
- **Stress Testing** - DoS resistance, connection limits, and resource exhaustion testing
- **Security Reporting** - Professional reports in JSON, HTML, and text formats

## Quick Start

### Installation

**Requirements:**
- Python 3.12+ (with asyncio support)
- Package manager: uv (recommended) or pip
- Git

**Dependencies automatically installed:**
- `mcp` - Official Model Context Protocol SDK
- `click` - Modern command-line interface framework  
- `pydantic` - Data validation and settings management
- `aiohttp` - Async HTTP client/server framework
- `pyyaml` - YAML configuration file support
- `rich` - Terminal formatting and progress indicators
- `websockets` - WebSocket transport support
- `pytest` - Testing framework (development)

```bash
# Clone repository
git clone https://github.com/fear-ai/mcpred.git
cd mcpred

# Option 1: Install with uv (recommended - faster, better dependency resolution)
uv sync --dev

# Option 2: Install with pip (alternative method)
pip install -e .                    # Editable install for development
pip install -r requirements.txt     # Install exact dependency versions

# For pip users: install development dependencies separately
pip install pytest pytest-asyncio pytest-cov
```

### Basic Usage
```bash
# Create test definition (new recommended workflow)
mcpred conf                                   # Creates example.red
# Edit example.red with your target and settings
mcpred example.red                           # Run the test definition

# Direct command usage
mcpred discover https://api.example.com/mcp  # Discover capabilities (alias: dis)
mcpred scan https://api.example.com/mcp      # Security assessment (alias: sc)

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
Create test definitions or global configuration files, or validate existing configuration.

```bash
mcpred conf [OPTIONS] [FILENAME]
```

**Options:**
- `--type, -t` - Configuration type: `test` (default) or `global`

**Behavior:**
- Without filename: Creates `example.red` test definition (default) or `.mcpred` global config
- With filename: Validates the specified configuration file

**Examples:**
```bash
mcpred conf                        # Create example.red test definition
mcpred conf --type global          # Create .mcpred global configuration
mcpred conf mytest.red             # Validate mytest.red
mcpred conf --type test            # Create example.red (explicit)
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
- `--verbose, --verb` - Enable verbose output
- `--log-level, --loglev, -ll` - Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) [default: INFO] (overrides --verbose)
- `--log-file, --logfile, -lf` - Log file path
- `--version, -v` - Show version information
- `--help, -h` - Show help message

## Configuration

mcpred uses YAML configuration files for flexible, human-readable settings management.

### Global Configuration (.mcpred)

The `.mcpred` file contains global settings that apply to all mcpred operations. It's automatically loaded from the current directory if present. Create with `mcpred conf --type global`.

**YAML Format Features:**
- Human-readable hierarchical structure
- Comments supported with `#`
- Type-safe values (strings, numbers, booleans, arrays, objects)
- Multi-line strings and environment variable support

Create `.mcpred` global configuration:
```yaml
# Global Security Settings - applied to all tests
security:
  max_fuzz_requests: 100        # Maximum fuzzing requests per test
  malformed_rate: 0.3           # Percentage of malformed requests (0.0-1.0)
  enable_dangerous: false       # Enable dangerous tests (use with caution)
  max_connections: 50           # Maximum concurrent connections
  stress_duration: 60           # Stress test duration in seconds

# Global Transport Settings - network configuration
transport:
  total_timeout: 30.0           # Total operation timeout
  connect_timeout: 10.0         # Connection establishment timeout
  disable_ssl_verify: false     # Disable SSL certificate verification
  connection_limit: 100         # HTTP connection pool limit

# Global Reporting Settings - output configuration
reporting:
  output_dir: "./reports"       # Default output directory
  default_fmt: "text"          # Default format: text, html, json
  include_raw: true            # Include raw protocol data
  auto_open: false             # Auto-open HTML reports

# Global Application Settings
log_level: "INFO"              # Logging level
verbose: false                 # Verbose output mode
parallel_tests: true          # Run tests in parallel
fail_fast: false              # Stop on first failure
timeout: 300.0                # Global operation timeout
```

### Test Definition Files (.red)

Test definition files use `.red` extension and define complete security test configurations. They override global settings when specified.

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

## Development and Testing

### CLI Test Automation

mcpred includes comprehensive CLI validation tests with performance optimizations:

```bash
# Run all test suites (80+ tests, ~30 seconds with batch processing)
python test_cli.py

# Run specific test suite for faster feedback
python test_cli.py --suite basic       # Basic commands (19 tests)
python test_cli.py --suite options     # Option validation (40+ tests)  
python test_cli.py --suite files       # File operations (6 tests)
python test_cli.py --suite red         # .red file operations (6 tests)
python test_cli.py --suite logging     # Logging behavior (16 tests)
python test_cli.py --suite errors      # Error handling (25+ tests)

# Performance options
python test_cli.py --batch             # Parallel execution (default)
python test_cli.py --no-batch          # Sequential execution (debugging)
python test_cli.py --parallel          # Run test suites in parallel

# Development workflow
python test_cli.py --suite basic --batch    # Quick validation (~10 seconds)
```

**Test Suite Features:**
- **Batch Processing:** Runs tests in parallel using ThreadPoolExecutor for 75% speed improvement
- **Selective Testing:** Run individual test suites for faster development cycles
- **Comprehensive Coverage:** Tests CLI options, file operations, error handling, smart defaults
- **Network-Safe:** Uses mock URLs to avoid external dependencies

## Advanced Usage

### Smart Defaults
mcpred automatically selects appropriate defaults:
```bash
# https:// URLs automatically use https transport
mcpred sc https://api.example.com/mcp

# .html/.htm files automatically use html format  
mcpred sc https://api.example.com/mcp -o report.html

# WebSocket URLs automatically use websocket transport
mcpred dis wss://ws.example.com/mcp
```

### Logging and Debugging
```bash
# Verbose output with debug logging
mcpred sc https://api.example.com/mcp --loglev DEBUG -lf debug.log

# Note: --loglevel overrides --verbose flag
mcpred sc https://api.example.com/mcp --verbose -ll INFO  # Uses INFO level

# Custom timeout for slow servers
mcpred dis https://slow-api.example.com/mcp --time 120
```

### Multiple Output Formats
mcpred automatically generates both requested format and HTML for analysis:
```bash
# Generates both report.json and report.html
mcpred sc https://api.example.com/mcp -o report.json --fmt json
```

## Requirements

- **Python 3.12+** - Modern async support required
- **Package manager** - UV (recommended) or pip with requirements.txt
- **MCP server access** - Target servers must be accessible for testing

### Installation Methods

**UV (Recommended):**
```bash
uv sync --dev
```
- **Faster**: 10-100x faster than pip
- **Better dependency resolution**: Handles conflicts automatically
- **Lock file**: Reproducible builds across environments

**Pip (Alternative):**
```bash
pip install -e .                    # Editable development install
pip install -r requirements.txt     # Exact versions from uv
pip install pytest pytest-asyncio pytest-cov  # Development dependencies
```
- **Editable install (`-e`)**: Source changes take effect immediately
- **Requirements.txt**: Generated from uv for pip compatibility
- **Development workflow**: Ideal for contributing or customizing

## Documentation

- **DESIGN.md** - Complete technical documentation and architecture details
- **GITHUB.md** - Repository management and security configuration guide  
- **TODO.md** - Development status and next steps for contributors

## Security Considerations

**AUTHORIZED TESTING ONLY** - This tool is designed for security research and authorized penetration testing.

- Only test servers you own or have explicit permission to test
- Some tests may impact server performance or availability  
- Follow responsible disclosure practices for any vulnerabilities discovered
- Use `enable_dangerous: false` in production environments

## Warnings and Disclaimers

### LEGAL DISCLAIMER

**AUTHORIZED USE ONLY**: This software is designed exclusively for authorized security testing, vulnerability research, and defensive security purposes. Users must obtain explicit written permission before testing any systems they do not own.

**LEGAL COMPLIANCE**: Users are solely responsible for ensuring their use of this software complies with all applicable local, state, national, and international laws and regulations. Unauthorized access to computer systems is illegal in most jurisdictions.

**NO WARRANTIES**: This software is provided "AS IS" without any warranties of any kind, either express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement.

### TECHNICAL RISKS AND LIMITATIONS

**SYSTEM IMPACT**: Security testing may cause:
- Temporary service degradation or unavailability
- Resource exhaustion on target systems
- Log file growth and storage consumption
- Network congestion or connection limits
- Unintended data exposure or modification

**ACCURACY LIMITATIONS**: 
- False positives and false negatives are possible
- Test results may not reflect all security vulnerabilities
- Protocol implementations may behave differently than expected
- Network conditions can affect test reliability and completeness

**SCOPE LIMITATIONS**:
- Tests focus on MCP protocol implementation security
- Operating system and infrastructure security is not assessed
- Application logic vulnerabilities may not be detected
- Third-party integrations and dependencies are not evaluated

### RESPONSIBLE USE GUIDELINES

**DEFENSIVE SECURITY FOCUS**: This tool is designed to improve security through:
- Vulnerability identification and remediation
- Security control validation and verification
- Compliance testing and risk assessment
- Defensive security posture improvement

**RESPONSIBLE DISCLOSURE**: When vulnerabilities are discovered:
- Report findings to system owners immediately
- Provide detailed technical information for remediation
- Allow reasonable time for fixes before public disclosure
- Follow coordinated vulnerability disclosure practices
- Document and preserve evidence for security improvement

**OPERATIONAL SAFETY**:
- Start with minimal test parameters and increase gradually
- Monitor system performance during testing
- Have rollback procedures ready for production systems
- Maintain detailed logs of all testing activities
- Coordinate with system administrators and security teams

### LIABILITY AND DAMAGES

**LIMITATION OF LIABILITY**: Under no circumstances shall the authors, contributors, or distributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages arising from the use of this software.

**USER RESPONSIBILITY**: Users acknowledge they use this software at their own risk and are fully responsible for any consequences, damages, or legal issues resulting from its use.

**INDEMNIFICATION**: Users agree to indemnify and hold harmless the software authors and contributors from any claims, damages, losses, or legal actions arising from unauthorized or improper use of this software.

## Support

- **Issues**: https://github.com/fear-ai/mcpred/issues
- **Security**: Report vulnerabilities to respective vendors following responsible disclosure practices
