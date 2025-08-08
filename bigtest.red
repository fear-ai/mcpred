# Big test definition - comprehensive security assessment
# Usage: mcpred bigtest.red

target: "https://production.example.com/mcp"
transport: "https"
output: "bigtest-results.html"
format: "html"

# Test selection - comprehensive assessment
auth: true
discovery: true  
fuzz: true
stress: true

# Aggressive security testing parameters
security:
  max_fuzz_requests: 500
  malformed_rate: 0.4
  max_connections: 100
  stress_duration: 120
  request_rate: 25
  enable_dangerous: true

# Extended transport timeouts for thorough testing
transport_config:
  total_timeout: 60.0
  connect_timeout: 20.0
  response_timeout: 10.0
  connection_limit: 200
  per_host_limit: 50