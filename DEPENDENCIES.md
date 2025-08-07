# mcpred Dependencies

## Installation Status
❌ **Dependencies not installed yet**  
⚠️  **Tests cannot run until dependencies are installed**

## Required Dependencies

### Core Runtime Dependencies
```bash
pip install mcp aiohttp websockets pydantic click pyyaml rich
```

| Package | Version | Purpose |
|---------|---------|---------|
| `mcp` | latest | Official MCP Python SDK (foundation) |
| `aiohttp` | latest | HTTP client for async operations |
| `websockets` | latest | WebSocket transport support |
| `pydantic` | latest | Data validation and configuration |
| `click` | latest | CLI framework |
| `pyyaml` | latest | YAML configuration file support |
| `rich` | latest | Terminal formatting and progress bars |

### Development Dependencies
```bash
pip install pytest pytest-asyncio pytest-cov
```

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | latest | Testing framework |
| `pytest-asyncio` | latest | Async test support |
| `pytest-cov` | latest | Code coverage reporting |

### Optional Dependencies
```bash
pip install jsonschema faker
```

| Package | Version | Purpose |
|---------|---------|---------|
| `jsonschema` | latest | JSON schema validation (optional) |
| `faker` | latest | Test data generation for fuzzing (optional) |

## Installation Methods

### Option 1: UV (Recommended - 10-100x faster)
```bash
# Install UV
curl -LsSf https://astral.sh/uv/install.sh | sh

# Initialize project
cd /Users/walter/Work/Github/mcpred
uv init --python 3.11

# Install dependencies
uv add mcp aiohttp websockets pydantic click pyyaml rich
uv add --dev pytest pytest-asyncio pytest-cov

# Run tests
uv run pytest tests/ -v
```

### Option 2: Traditional pip
```bash
cd /Users/walter/Work/Github/mcpred

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install mcp aiohttp websockets pydantic click pyyaml rich
pip install pytest pytest-asyncio pytest-cov

# Run tests
python -m pytest tests/ -v
```

### Option 3: pip-tools (for production)
```bash
# Create requirements files
echo "mcp
aiohttp
websockets  
pydantic
click
pyyaml
rich" > requirements.txt

echo "pytest
pytest-asyncio
pytest-cov" > dev-requirements.txt

# Install
pip install -r requirements.txt -r dev-requirements.txt
```

## Testing After Installation

Once dependencies are installed, run:

```bash
# Test package imports
python -c "import mcpred; print('✅ Package imports successfully')"

# Run test suite
python -m pytest tests/ -v --tb=short

# Run with coverage
python -m pytest tests/ --cov=mcpred --cov-report=html

# Test CLI
python -m mcpred.cli.main --help
```

## Known Issues

1. **MCP SDK Compatibility**: Requires official MCP Python SDK
2. **Python Version**: Tested with Python 3.11+
3. **Async Support**: Requires pytest-asyncio for async tests

## Next Steps After Installation

1. Run test suite to validate implementation
2. Fix any import or compatibility issues
3. Test CLI commands
4. Create pyproject.toml with pinned versions
5. Set up CI/CD pipeline