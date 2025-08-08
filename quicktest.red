# Quick test definition - discovery only
# Usage: mcpred quicktest.red

target: "https://dev.example.com/mcp"
format: "text"

# Only run discovery, skip intensive tests
auth: false
discovery: true
fuzz: false
stress: false