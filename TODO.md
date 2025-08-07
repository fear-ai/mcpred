# mcpred Development Tasks

**Current Status**: 89/109 tests passing (82% success rate), production-ready core functionality

## Immediate Priority

### Fix Test Infrastructure
- [ ] **Async context manager mocking** - Fix transport test failures (20 tests failing)
- [ ] **Mock configuration issues** - Resolve VulnDetector mock setup problems (4 tests)  
- [ ] **Achieve 95+ test success rate** - Target for production confidence

### GitHub Actions CI/CD
- [ ] **Set up automated testing** - Multi-Python version testing (3.11, 3.12)
- [ ] **Security scanning integration** - Bandit, dependency scanning
- [ ] **Status checks** - Branch protection with required CI passes
- [ ] **Automated security alerts** - Enable all GitHub security features

## Development Improvements

### CLI Enhancements
- [ ] **Complete missing commands** - Implement `auth`, `fuzz`, `stress` commands referenced in main CLI
- [ ] **Progress indicators** - Add Rich progress bars for long-running operations
- [ ] **Error handling** - Improve user-friendly error messages and recovery
- [ ] **Bash/zsh completion** - Command completion for better user experience

### Security Testing Accuracy
- [ ] **False positive reduction** - Improve vulnerability detection accuracy
- [ ] **Risk scoring refinement** - Better CVSS-style severity classification
- [ ] **Detection pattern updates** - Enhance information disclosure detection
- [ ] **Performance test tuning** - Optimize stress testing parameters

### Integration Testing
- [ ] **Real MCP server testing** - Test against known MCP implementations
- [ ] **Reference server setup** - Docker containers for consistent testing
- [ ] **Integration test infrastructure** - Framework for live server testing
- [ ] **Compatibility validation** - Ensure works with major MCP servers

## Feature Extensions

### Transport Support
- [ ] **Custom protocols** - Support for non-standard MCP transports
- [ ] **Connection pooling** - Improve efficiency for large-scale testing
- [ ] **TLS/SSL testing** - Certificate validation and security analysis
- [ ] **Proxy support** - HTTP proxy and SOCKS support for enterprise environments

### Advanced Security Features
- [ ] **Plugin architecture** - Extensible security test modules
- [ ] **Custom payloads** - User-defined fuzzing patterns
- [ ] **Vulnerability correlation** - Cross-reference with CVE databases
- [ ] **Compliance reporting** - Generate compliance-specific reports

### Reporting Enhancements  
- [ ] **PDF export** - Professional PDF reports for executive summaries
- [ ] **Trend analysis** - Historical vulnerability tracking
- [ ] **Executive dashboards** - High-level risk visualization
- [ ] **Integration APIs** - REST API for toolchain integration

## Open Issues

### Technical Debt
- [ ] **Import path cleanup** - Remove sys.path manipulation, use proper packaging
- [ ] **Configuration consolidation** - Reduce config validation complexity
- [ ] **Error handling standardization** - Consistent exception handling patterns
- [ ] **Logging improvements** - Better structured logging with correlation IDs

### Documentation Gaps
- [ ] **Security testing methodology** - Document testing approaches and rationale
- [ ] **Vulnerability classification** - Clear criteria for risk assessment
- [ ] **Integration examples** - Real-world usage scenarios and case studies
- [ ] **Troubleshooting guide** - Common issues and solutions

### Security Concerns
- [ ] **Tool security audit** - External security review of mcpred itself
- [ ] **Dependency monitoring** - Automated vulnerability scanning for dependencies
- [ ] **Usage tracking ethics** - Ensure no unauthorized testing capabilities
- [ ] **Responsible disclosure** - Formalize vulnerability disclosure process

## Architecture Evolution

### Scalability
- [ ] **Concurrent testing optimization** - Improve async performance  
- [ ] **Memory usage optimization** - Handle large-scale testing efficiently
- [ ] **Result caching** - Cache discovery results for repeated testing
- [ ] **Distributed testing** - Multi-node testing capability

### Enterprise Features
- [ ] **SAML/OAuth integration** - Enterprise authentication support
- [ ] **Audit logging** - Comprehensive activity logging for compliance
- [ ] **Policy enforcement** - Organizational testing policy compliance
- [ ] **Multi-tenancy** - Support for multiple teams/organizations

### Community Features
- [ ] **Vulnerability database** - Curated MCP vulnerability knowledge base
- [ ] **Community contributions** - Issue templates, contribution guidelines
- [ ] **Security advisories** - Public disclosure of resolved vulnerabilities
- [ ] **Best practices guide** - Security testing methodology documentation

## Research Opportunities

### MCP Protocol Security
- [ ] **Protocol vulnerability research** - Deep analysis of MCP security model
- [ ] **Attack surface mapping** - Comprehensive MCP attack vector analysis
- [ ] **Security pattern analysis** - Common vulnerability patterns in MCP servers
- [ ] **Defensive recommendations** - Best practices for secure MCP implementation

### Tool Enhancement
- [ ] **Machine learning integration** - ML-powered vulnerability detection
- [ ] **Behavioral analysis** - Anomaly detection in server responses
- [ ] **Automated exploit generation** - Proof-of-concept generation for findings
- [ ] **Threat modeling integration** - STRIDE/PASTA methodology integration

## Next Sprint Focus

**Priority order for immediate development:**
1. Fix async test mocking issues (blocking 95+ test success)
2. Set up GitHub Actions CI/CD pipeline
3. Complete missing CLI commands (`auth`, `fuzz`, `stress`)
4. Integration testing framework with real servers
5. False positive reduction in security detection

**Success criteria:**
- 95+ unit tests passing
- CI/CD pipeline operational  
- Integration tests running against reference servers
- Core security detection accuracy validated

This TODO serves as the active development roadmap for mcpred, focusing on production readiness and security research community adoption.