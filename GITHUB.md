# mcpred GitHub Management Guide

## 📊 Repository Status

**🌐 Repository**: https://github.com/fear-ai/mcpred  
**✅ Status**: Live and production-ready  
**📈 Tests**: 89/109 passing (82% success rate)  
**🛡️ Security**: Defensive security tool for MCP server testing  

---

## 🚀 Quick Start (New Contributors)

### **1. Clone and Setup**
```bash
git clone https://github.com/fear-ai/mcpred.git
cd mcpred
uv sync --dev
uv run pytest tests/unit/ -v
```

### **2. Basic Development Workflow**
```bash
# Create feature branch
git checkout -b feature/your-feature

# Make changes and test
uv run pytest tests/unit/ -v
uv run python -m cli.main --help

# Submit pull request
git push -u origin feature/your-feature
# Open PR on GitHub
```

---

## 🔒 Security Configuration (Repository Owners)

### **Essential Security Features (Do This First)**
```bash
# Enable critical security monitoring
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph
```

**Why Critical for mcpred:**
- 🛡️ **Security tool must have secure dependencies**
- 🔍 **Monitors 7 core + 3 dev dependencies for vulnerabilities**
- ⚡ **Real-time alerts for Python/async library security issues**
- 📊 **Dependency graph shows complete security posture**

### **Branch Protection (Team Development)**
```bash
# Protect main branch from direct pushes
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":[]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field allow_force_pushes=false \
  --field allow_deletions=false
```

**Protection Rules:**
- ✅ **Required PR reviews** - No direct commits to main
- ✅ **Up-to-date branches** - Must merge latest changes first  
- ✅ **Admin enforcement** - Rules apply to all users
- 🚫 **No force pushes** - Preserves git history
- 🚫 **No branch deletion** - Protects main branch

---

## ⚙️ Development Workflows

### **For Individual Developers**
```bash
# Basic security setup (recommended)
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts

# Standard workflow - no branch protection needed
git clone https://github.com/fear-ai/mcpred.git
# Make changes directly to main
git add -A && git commit -m "Your changes"
git push
```

### **For Team Development**
```bash
# Full security + branch protection
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph

# Enable branch protection
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_pull_request_reviews='{"required_approving_review_count":1}'

# Team workflow - PR required
git checkout -b feature/my-feature
# Make changes
git push -u origin feature/my-feature
# Create PR for review
```

### **For Enterprise/Security-Critical Use**
```bash
# Maximum security configuration
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph

# Strict branch protection
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test-suite","security-scan"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  }' \
  --field allow_force_pushes=false \
  --field allow_deletions=false
```

---

## 🔧 CI/CD Integration

### **GitHub Actions Workflow (Recommended)**

Create `.github/workflows/ci.yml`:
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
        run: uv run bandit -r mcpred/ -f json -o security-report.json
```

### **Status Check Integration**
After setting up CI, update branch protection:
```bash
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test (3.11)","test (3.12)"]}'
```

---

## 📋 Advanced Security Features

### **1. Dependabot Configuration**

Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    reviewers:
      - "fear-ai"
    commit-message:
      prefix: "deps"
      include: "scope"
```

### **2. Security Policy**

Create `.github/SECURITY.md`:
```markdown
# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities to: security@fear-ai.com

- ✅ **Response time**: Within 48 hours
- 🔒 **Disclosure**: Coordinated disclosure preferred
- 🎯 **Scope**: mcpred security vulnerabilities only

## Security Testing Guidelines

This is a security testing tool. Please:
- Only test authorized systems
- Follow responsible disclosure
- Report mcpred bugs, not target vulnerabilities
```

### **3. CodeQL Analysis**

Create `.github/workflows/codeql.yml`:
```yaml
name: "Security Analysis"

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

---

## 🎯 Use Case Configurations

### **Personal Security Research**
**Needs**: Basic security alerts, simple workflow
```bash
gh repo edit fear-ai/mcpred --enable-security-alerts
# Clone, develop, push directly to main
```

### **Open Source Project**
**Needs**: Community contributions, quality control
```bash
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
# Enable PR reviews for contributors
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_pull_request_reviews='{"required_approving_review_count":1}'
```

### **Enterprise Security Tool**
**Needs**: Maximum security, audit trail, compliance
```bash
# Full security suite + strict branch protection
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts  
gh repo edit fear-ai/mcpred --enable-dependency-graph

# Strict controls
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test-suite","security-scan","compliance-check"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 2,
    "dismiss_stale_reviews": true
  }'
```

### **Security Research Team**
**Needs**: Collaborative development, security focus
```bash
# Security monitoring + team workflow
gh repo edit fear-ai/mcpred --enable-security-alerts
gh repo edit fear-ai/mcpred --enable-vulnerability-alerts
gh repo edit fear-ai/mcpred --enable-dependency-graph

# Team-friendly protection
gh api repos/fear-ai/mcpred/branches/main/protection \
  --method PUT \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field enforce_admins=false  # Allow admin overrides for urgent fixes
```

---

## 📊 Security Monitoring Dashboard

### **Check Security Status**
```bash
# View current security settings
gh api repos/fear-ai/mcpred | jq '.security_and_analysis'

# Check branch protection
gh api repos/fear-ai/mcpred/branches/main/protection

# View recent security alerts
gh api repos/fear-ai/mcpred/security-advisories
```

### **Security Metrics to Monitor**
- 🔍 **Vulnerability alerts**: Zero unresolved high/critical
- 📊 **Dependency updates**: Weekly Dependabot PRs
- 🛡️ **Branch protection**: 100% PR review compliance
- ⚡ **CI status**: All checks passing
- 🔒 **Secret scanning**: No exposed credentials

---

## 🚨 Security Best Practices

### **For mcpred as Security Tool**
1. **Dependencies**: Always use latest secure versions
2. **Testing**: 89+ tests passing before release
3. **Documentation**: Security warnings in CLI help
4. **Disclosure**: Responsible vulnerability reporting
5. **Usage**: Clear authorized-testing-only messaging

### **Repository Security**
1. **Monitoring**: All security features enabled
2. **Access**: Minimal required permissions
3. **Reviews**: All changes reviewed before merge
4. **Audit**: Full git history preserved
5. **Compliance**: Meet organizational security standards

---

## 📝 Quick Reference

### **Essential Commands**
```bash
# Repository setup
git clone https://github.com/fear-ai/mcpred.git
uv sync --dev

# Security enablement  
gh repo edit fear-ai/mcpred --enable-security-alerts

# Branch protection
gh api repos/fear-ai/mcpred/branches/main/protection --method PUT

# Status checking
gh api repos/fear-ai/mcpred/branches/main/protection
```

### **Support Resources**
- 📚 **Documentation**: See README.md and DESIGN.md
- 🐛 **Issues**: https://github.com/fear-ai/mcpred/issues
- 🔒 **Security**: Follow .github/SECURITY.md guidelines
- 💬 **Discussions**: Use GitHub discussions for questions

This comprehensive guide ensures mcpred maintains the highest security standards while supporting various development workflows from individual research to enterprise deployments! 🛡️