# mcpred Repository Management Guide

Repository: https://github.com/fear-ai/mcpred

## Project Layout Considerations

### Documentation Strategy
- **README.md** - Visitor introduction and usage guide
- **DESIGN.md** - Complete technical documentation and architecture
- **GITHUB.md** - Repository administration and management workflows
- **TODO.md** - Active development tasks and next steps

### Code Organization Principles
- **Modular architecture** - Clear separation between core, security, reporting, config, CLI
- **Single-level package structure** - Direct imports, no nested package directories
- **Test-driven development** - Comprehensive unit and integration test suites
- **Professional tooling** - UV dependency management, pytest testing, rich CLI output

## Repository Administration

### Essential Security Features

**Critical for security tools:**
```bash
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph
```

**Rationale:**
- Security tools must maintain secure supply chain
- Monitor 10 dependencies (7 runtime + 3 dev) for vulnerabilities
- Real-time alerts for Python async library security issues
- Dependency graph shows complete security posture

### Development Workflow Management

#### Individual Development
```bash
# Basic security monitoring
gh repo edit fear-ai/mcpred --enable-security-alerts

# Direct development workflow
git clone https://github.com/fear-ai/mcpred.git
git add -A && git commit -m "Changes"
git push
```

#### Team Development  
```bash
# Full security suite
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph

# Branch protection for code review
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field allow_force_pushes=false
```

#### Enterprise/Security-Critical
```bash
# Maximum security configuration
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph

# Strict controls with status checks
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test-suite","security-scan"]}' \
  --field required_pull_request_reviews='{"required_approving_review_count":2,"dismiss_stale_reviews":true}' \
  --field enforce_admins=true
```

## CI/CD Integration

### GitHub Actions Configuration

**Recommended workflow** (`.github/workflows/ci.yml`):
```yaml
name: CI/CD Pipeline
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']
    steps:
      - uses: actions/checkout@v4
      - name: Install UV
        run: curl -LsSf https://astral.sh/uv/install.sh | sh
      - name: Install dependencies  
        run: uv sync --dev
      - name: Run tests
        run: uv run pytest tests/unit/ -v --cov=mcpred
      - name: Test CLI
        run: uv run python -m cli.main --help
      - name: Security scan
        run: uv run bandit -r mcpred/ -f json
```

**Status check integration:**
```bash
# After CI setup, require status checks
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test (3.11)","test (3.12)"]}'
```

## Advanced Repository Features

### Dependabot Configuration
**File:** `.github/dependabot.yml`
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    reviewers: ["fear-ai"]
    commit-message:
      prefix: "deps"
```

### Security Policy
**File:** `.github/SECURITY.md`
```markdown
# Security Policy

## Reporting Vulnerabilities
Report security issues to: security@fear-ai.com
- Response time: Within 48 hours
- Coordinated disclosure preferred
- Scope: mcpred vulnerabilities only

## Security Testing Guidelines
- Only test authorized systems
- Follow responsible disclosure
- Report tool bugs, not target vulnerabilities
```

### CodeQL Analysis
**File:** `.github/workflows/codeql.yml`
```yaml
name: Security Analysis
on:
  push: [main]
  pull_request: [main]
  schedule: [{cron: '0 6 * * 1'}]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with: {languages: python}
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

## Repository Monitoring

### Security Status Verification
```bash
# Check current security settings
gh api repos/fear-ai/mcpred | jq '.security_and_analysis'

# Verify branch protection
gh api repos/fear-ai/mcpred/branches/main/protection

# Review security advisories
gh api repos/fear-ai/mcpred/security-advisories
```

### Key Metrics to Monitor
- **Vulnerability alerts**: Zero unresolved high/critical issues
- **Dependency updates**: Weekly Dependabot PRs processed
- **Branch protection**: 100% PR review compliance maintained
- **CI/CD status**: All automated checks passing consistently
- **Test coverage**: Maintain 80+ test success rate

## Repository Best Practices

### Security Tool Specific Considerations
1. **Dependency vigilance** - Security tools require extra dependency monitoring
2. **Clear usage warnings** - Prominent authorized-testing-only messaging
3. **Vulnerability disclosure** - Established process for reporting issues
4. **Community trust** - Transparent development and security practices
5. **Regular audits** - Periodic security review of tool implementation

### Access Control Strategy  
- **Minimal permissions** - Grant only necessary repository access
- **Admin controls** - Use branch protection even for administrators
- **Audit logging** - Monitor all repository access and changes
- **Key rotation** - Regular review and rotation of access credentials

### Release Management
- **Semantic versioning** - Clear version numbering for security releases
- **Security releases** - Fast-track critical security updates
- **Change documentation** - Comprehensive changelog with security notes
- **Backwards compatibility** - Careful API evolution for tool integrations

## Integration Considerations

### Security Tool Ecosystem
- **Tool chaining** - JSON output format supports automation
- **CI/CD integration** - Compatible with security scanning pipelines  
- **Enterprise deployment** - Configuration management for large-scale use
- **Compliance reporting** - Structured output for audit requirements

### Community Engagement
- **Issue templates** - Structured bug reports and feature requests
- **Contributing guidelines** - Clear development and security standards
- **Discussion forums** - GitHub discussions for community questions
- **Security advisories** - Public disclosure of resolved security issues

This guide focuses specifically on repository management aspects unique to maintaining a security testing tool, ensuring both development efficiency and security community trust.