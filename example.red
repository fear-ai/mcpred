target: https://api.example.com/mcp
transport: https
output: security-report.html
format: html
auth: true
discovery: true
fuzz: true
stress: false
security:
  max_fuzz_requests: 50
  malformed_rate: 0.2
  stress_duration: 30
  enable_dangerous: false
transport_config:
  total_timeout: 60.0
  connection_limit: 25
  disable_ssl_verify: false
