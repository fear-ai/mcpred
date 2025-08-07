# mcpred - MCP Red Team Client

A Python-based command line MCP client for red teaming and security testing. Exercise and test remote MCP servers to identify vulnerabilities and weaknesses.

##  Project Status

**READY FOR TESTING** - Core implementation and dependencies are complete!

-  **Core Implementation**: Complete with 2000+ lines of security-focused code
-  **Dependencies**: Installed via UV with pyproject.toml configuration
-  **Architecture**: Modular design with pluggable transports and test modules
-  **CLI Interface**: Professional command-line tool with rich output
-  **Test Suite**: 100+ unit tests ready to run
- >ê **Ready for validation**: Run `uv run pytest tests/ -v` to validate

## Quick Start

### Run Tests
```bash
cd /Users/walter/Work/Github/mcpred

# Run all tests
uv run pytest tests/ -v --tb=short

# Run with coverage
uv run pytest tests/ --cov=mcpred --cov-report=html
```

### Basic Usage
```bash
# Test package import
uv run python -c "import mcpred; print(' mcpred ready to use')"

# Discover server capabilities
uv run python -m mcpred.cli.main discover http://localhost:8080

# Comprehensive security scan  
uv run python -m mcpred.cli.main scan http://localhost:8080 --all-tests

# Generate HTML report
uv run python -m mcpred.cli.main scan http://localhost:8080 -o report.html --format html
```

## Architecture

### Core Components
- **MCPTeamClient**: Main client with security testing capabilities
- **SecSessionManager**: Security-enhanced session with vulnerability detection  
- **Transport Factory**: HTTP, stdio, WebSocket transports with security monitoring
- **Security Modules**: Discovery, authentication testing, protocol fuzzing, stress testing

### Security Testing Features
- **= Discovery Engine**: Server enumeration and capability detection with fingerprinting
- **= Authentication Testing**: OAuth bypass, token manipulation, privilege escalation
- **=( Protocol Fuzzing**: JSON-RPC malformation testing with 8 payload generators
- **¡ Stress Testing**: DoS resistance, connection limits, memory exhaustion
- **=Ê Vulnerability Analysis**: Automated classification with severity scoring

### Reporting System
- **Multiple Formats**: JSON (automation), HTML (viewing), Text (terminal)
- **Executive Summaries**: Risk-based reporting with compliance implications
- **Detailed Findings**: Technical vulnerability details with remediation advice
- **Export Options**: File output with automatic format detection

## Commands

### Discovery
```bash
# Basic server discovery
uv run python -m mcpred.cli.main discover http://localhost:8080

# With fingerprinting and detailed output
uv run python -m mcpred.cli.main discover http://localhost:8080 --fingerprint --show-tools --show-resources
```

### Security Scanning
```bash
# Full security assessment
uv run python -m mcpred.cli.main scan http://localhost:8080 --all-tests

# Skip specific test types
uv run python -m mcpred.cli.main scan http://localhost:8080 --skip-fuzz --skip-stress

# Multiple output formats
uv run python -m mcpred.cli.main scan http://localhost:8080 -o report --format html
```

### Configuration
```bash
# Initialize sample config
uv run python -m mcpred.cli.main init

# Validate configuration
uv run python -m mcpred.cli.main validate

# Show version
uv run python -m mcpred.cli.main version
```

## Configuration

Create `.mcpred.yaml` in your project directory:

```yaml
targets:
  - url: "http://localhost:8080"
    transport_type: "http" 
    name: "local-server"

security:
  max_fuzz_requests: 100
  malformed_rate: 0.3
  enable_dangerous_tests: false

reporting:
  output_directory: "./reports"
  default_format: "json"
  include_raw_data: true

log_level: "INFO"
verbose: false
```

## Dependencies

All dependencies are managed via UV and defined in `pyproject.toml`:

### Core Runtime
- **mcp** (1.12.3+): Official MCP Python SDK
- **aiohttp** (3.12.15+): HTTP client for async operations
- **websockets** (15.0.1+): WebSocket transport support  
- **pydantic** (2.11.7+): Data validation and configuration
- **click** (8.2.1+): CLI framework
- **pyyaml** (6.0.2+): YAML configuration file support
- **rich** (14.1.0+): Terminal formatting and progress bars

### Development
- **pytest** (8.4.1+): Testing framework
- **pytest-asyncio** (1.1.0+): Async test support
- **pytest-cov** (6.2.1+): Code coverage reporting

## Development

### Testing
```bash
# Run all tests with verbose output
uv run pytest tests/ -v

# Run with coverage report
uv run pytest tests/ --cov=mcpred --cov-report=html

# Run specific test categories
uv run pytest tests/unit/ -v           # Unit tests only
uv run pytest tests/integration/ -v    # Integration tests (requires servers)
```

### Code Quality
```bash
# Install quality tools
uv add --dev black ruff mypy

# Format code
uv run black mcpred/ tests/

# Lint
uv run ruff mcpred/ tests/

# Type checking  
uv run mypy mcpred/
```

## Security Notice

**  IMPORTANT**: This tool is designed for authorized security testing only.

- Only test servers you own or have explicit permission to test
- Some tests may impact server performance or availability
- Use `enable_dangerous_tests: false` in production environments
- Follow responsible disclosure practices for any vulnerabilities found

## Contributing

1. Clone and install: `uv sync --dev`
2. Run tests: `uv run pytest tests/ -v`
3. Follow existing code patterns and security-first design
4. Add tests for new functionality
5. Update documentation

## Next Steps

1. **Validate Implementation**: `uv run pytest tests/ -v`
2. **Test CLI Commands**: Try discovery and scanning commands
3. **Create Sample Config**: `uv run python -m mcpred.cli.main init`
4. **Run Against Test Server**: Test with real MCP server
5. **Generate Reports**: Try different output formats

## Status

- **Phase**: Ready for testing and validation
- **Dependencies**:  Installed and managed via UV  
- **Tests**:  Comprehensive suite ready to run
- **CLI**:  Complete command interface
- **Goal**: Production-ready MCP security testing tool