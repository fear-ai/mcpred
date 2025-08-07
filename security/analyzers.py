"""
Vulnerability analysis and classification.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import re


logger = logging.getLogger(__name__)


class Severity(Enum):
    """Security issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(Enum):
    """Categories of security vulnerabilities."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PROTOCOL_VIOLATION = "protocol_violation"
    DENIAL_OF_SERVICE = "denial_of_service"
    CONFIGURATION = "configuration"
    INJECTION = "injection"
    SESSION_MANAGEMENT = "session_management"
    CRYPTOGRAPHY = "cryptography"


class VulnerabilityFinding:
    """Represents a classified vulnerability finding."""
    
    def __init__(
        self,
        title: str,
        description: str,
        severity: Severity,
        category: VulnerabilityCategory,
        **kwargs
    ):
        self.title = title
        self.description = description
        self.severity = severity
        self.category = category
        self.evidence = kwargs.get("evidence", {})
        self.recommendations = kwargs.get("recommendations", [])
        self.references = kwargs.get("references", [])
        self.cve_score = kwargs.get("cve_score", 0.0)
        self.exploitability = kwargs.get("exploitability", "unknown")
        self.affected_components = kwargs.get("affected_components", [])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "evidence": self.evidence,
            "recommendations": self.recommendations,
            "references": self.references,
            "cve_score": self.cve_score,
            "exploitability": self.exploitability,
            "affected_components": self.affected_components
        }


class VulnAnalyzer:
    """Vulnerability analysis and classification engine."""
    
    def __init__(self):
        self.findings: List[VulnerabilityFinding] = []
        self.classification_rules = self._initialize_classification_rules()
    
    def analyze_security_issues(self, security_issues: List[Dict[str, Any]]) -> List[VulnerabilityFinding]:
        """Analyze and classify security issues."""
        logger.info(f"Analyzing {len(security_issues)} security issues")
        
        findings = []
        
        for issue in security_issues:
            try:
                finding = self._classify_issue(issue)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to classify issue {issue}: {e}")
        
        self.findings.extend(findings)
        logger.info(f"Classified {len(findings)} vulnerability findings")
        return findings
    
    def analyze_protocol_violations(self, violations: List[Any]) -> List[VulnerabilityFinding]:
        """Analyze protocol violations for security implications."""
        logger.info(f"Analyzing {len(violations)} protocol violations")
        
        findings = []
        
        for violation in violations:
            try:
                finding = self._classify_protocol_violation(violation)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to classify protocol violation {violation}: {e}")
        
        self.findings.extend(findings)
        return findings
    
    def analyze_stress_test_results(self, stress_results: List[Any]) -> List[VulnerabilityFinding]:
        """Analyze stress test results for DoS vulnerabilities."""
        logger.info(f"Analyzing {len(stress_results)} stress test results")
        
        findings = []
        
        for result in stress_results:
            try:
                finding = self._classify_stress_result(result)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to classify stress result {result}: {e}")
        
        self.findings.extend(findings)
        return findings
    
    def _classify_issue(self, issue: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Classify a generic security issue."""
        issue_type = issue.get("type", "unknown")
        severity_str = issue.get("severity", "low")
        description = issue.get("description", "No description")
        
        # Map severity string to enum
        severity = self._parse_severity(severity_str)
        
        # Apply classification rules
        for rule in self.classification_rules:
            if rule["matcher"](issue):
                return VulnerabilityFinding(
                    title=rule["title"](issue),
                    description=rule["description"](issue),
                    severity=rule["severity"](issue, severity),
                    category=rule["category"],
                    evidence=issue,
                    recommendations=rule.get("recommendations", []),
                    references=rule.get("references", [])
                )
        
        # Default classification if no rules match
        category = self._infer_category_from_type(issue_type)
        return VulnerabilityFinding(
            title=f"Security Issue: {issue_type}",
            description=description,
            severity=severity,
            category=category,
            evidence=issue
        )
    
    def _classify_protocol_violation(self, violation: Any) -> Optional[VulnerabilityFinding]:
        """Classify a protocol violation."""
        if hasattr(violation, 'to_dict'):
            violation_data = violation.to_dict()
        else:
            violation_data = violation if isinstance(violation, dict) else {"violation": str(violation)}
        
        violation_type = violation_data.get("type", "unknown")
        
        # Protocol violations are generally medium severity
        severity = Severity.MEDIUM
        category = VulnerabilityCategory.PROTOCOL_VIOLATION
        
        title = f"Protocol Violation: {violation_type}"
        description = f"Server accepted malformed or invalid protocol request: {violation_type}"
        
        recommendations = [
            "Implement strict JSON-RPC schema validation",
            "Return proper error responses for malformed requests",
            "Add request size limits and validation"
        ]
        
        # Adjust severity based on violation type
        if "crash" in violation_type or "server_error" in violation_type:
            severity = Severity.HIGH
            recommendations.append("Implement proper error handling to prevent crashes")
        elif "malformed_accepted" in violation_type:
            severity = Severity.MEDIUM
            recommendations.append("Reject malformed requests with appropriate error codes")
        
        return VulnerabilityFinding(
            title=title,
            description=description,
            severity=severity,
            category=category,
            evidence=violation_data,
            recommendations=recommendations
        )
    
    def _classify_stress_result(self, result: Any) -> Optional[VulnerabilityFinding]:
        """Classify a stress test result."""
        if hasattr(result, 'metrics'):
            metrics = result.metrics
            test_type = result.test_type
            success = result.success
        else:
            metrics = result if isinstance(result, dict) else {}
            test_type = metrics.get("test_type", "unknown")
            success = metrics.get("success", False)
        
        if not success:
            return None  # No vulnerability found
        
        vulnerability_type = metrics.get("vulnerability_type", "unknown")
        
        # Map stress test results to findings
        if test_type == "connection_limits":
            return self._classify_connection_limit_vulnerability(metrics)
        elif test_type == "resource_exhaustion":
            return self._classify_resource_exhaustion_vulnerability(metrics)
        elif test_type == "slowloris":
            return self._classify_slowloris_vulnerability(metrics)
        elif test_type == "memory_exhaustion":
            return self._classify_memory_exhaustion_vulnerability(metrics)
        
        # Generic DoS vulnerability
        return VulnerabilityFinding(
            title=f"Denial of Service: {vulnerability_type}",
            description=f"Server is vulnerable to DoS attacks via {test_type}",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.DENIAL_OF_SERVICE,
            evidence=metrics,
            recommendations=[
                "Implement rate limiting",
                "Add connection limits",
                "Monitor resource usage",
                "Implement proper timeout mechanisms"
            ]
        )
    
    def _classify_connection_limit_vulnerability(self, metrics: Dict[str, Any]) -> VulnerabilityFinding:
        """Classify connection limit vulnerabilities."""
        vulnerability_type = metrics.get("vulnerability_type", "")
        successful_connections = metrics.get("successful_connections", 0)
        
        if vulnerability_type == "no_connection_limits":
            return VulnerabilityFinding(
                title="Denial of Service: Unlimited Connections",
                description=f"Server allows unlimited concurrent connections ({successful_connections}+ tested)",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.DENIAL_OF_SERVICE,
                evidence=metrics,
                recommendations=[
                    "Implement maximum concurrent connection limits",
                    "Add connection rate limiting",
                    "Monitor connection usage and implement alerting",
                    "Consider implementing connection queuing"
                ],
                exploitability="high"
            )
        elif vulnerability_type == "connection_refused":
            return VulnerabilityFinding(
                title="Availability Issue: Connection Refusal",
                description="Server refuses all connection attempts",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.DENIAL_OF_SERVICE,
                evidence=metrics,
                recommendations=[
                    "Check server configuration",
                    "Verify network connectivity",
                    "Review connection handling logic"
                ]
            )
        
        return None
    
    def _classify_resource_exhaustion_vulnerability(self, metrics: Dict[str, Any]) -> VulnerabilityFinding:
        """Classify resource exhaustion vulnerabilities."""
        vulnerability_type = metrics.get("vulnerability_type", "")
        error_rate = metrics.get("error_rate", 0)
        average_response_time = metrics.get("average_response_time", 0)
        
        if vulnerability_type == "service_degradation":
            return VulnerabilityFinding(
                title="Denial of Service: Service Degradation",
                description=f"Server performance degrades under load (error rate: {error_rate:.2%})",
                severity=Severity.MEDIUM,
                category=VulnerabilityCategory.DENIAL_OF_SERVICE,
                evidence=metrics,
                recommendations=[
                    "Implement request rate limiting",
                    "Optimize server resource usage",
                    "Add load balancing",
                    "Implement graceful degradation mechanisms"
                ]
            )
        elif vulnerability_type == "performance_degradation":
            return VulnerabilityFinding(
                title="Performance Issue: Slow Response Times",
                description=f"Server response times become excessive under load ({average_response_time:.2f}s average)",
                severity=Severity.LOW,
                category=VulnerabilityCategory.DENIAL_OF_SERVICE,
                evidence=metrics,
                recommendations=[
                    "Optimize server performance",
                    "Implement response time monitoring",
                    "Consider caching strategies",
                    "Review database query performance"
                ]
            )
        
        return None
    
    def _classify_slowloris_vulnerability(self, metrics: Dict[str, Any]) -> VulnerabilityFinding:
        """Classify Slowloris attack vulnerabilities."""
        return VulnerabilityFinding(
            title="Denial of Service: Slowloris Vulnerability",
            description=f"Server vulnerable to slow connection attacks ({metrics.get('active_slow_connections', 0)} slow connections maintained)",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.DENIAL_OF_SERVICE,
            evidence=metrics,
            recommendations=[
                "Implement connection timeouts",
                "Add slow connection detection",
                "Limit concurrent connections per IP",
                "Use a reverse proxy with timeout protection"
            ],
            exploitability="medium",
            references=["CVE-2007-6203"]
        )
    
    def _classify_memory_exhaustion_vulnerability(self, metrics: Dict[str, Any]) -> VulnerabilityFinding:
        """Classify memory exhaustion vulnerabilities."""
        vulnerability_type = metrics.get("vulnerability_type", "")
        
        severity_map = {
            "server_crash": Severity.CRITICAL,
            "memory_exhaustion": Severity.HIGH,
            "large_payload_acceptance": Severity.MEDIUM
        }
        
        severity = severity_map.get(vulnerability_type, Severity.MEDIUM)
        
        return VulnerabilityFinding(
            title=f"Denial of Service: {vulnerability_type.replace('_', ' ').title()}",
            description=f"Server vulnerable to memory exhaustion attacks: {metrics.get('description', '')}",
            severity=severity,
            category=VulnerabilityCategory.DENIAL_OF_SERVICE,
            evidence=metrics,
            recommendations=[
                "Implement request size limits",
                "Add memory usage monitoring",
                "Implement payload validation",
                "Use streaming for large requests",
                "Add circuit breakers for resource protection"
            ]
        )
    
    def _initialize_classification_rules(self) -> List[Dict[str, Any]]:
        """Initialize vulnerability classification rules."""
        return [
            {
                "matcher": lambda issue: issue.get("type") == "information_disclosure",
                "title": lambda issue: f"Information Disclosure: {issue.get('pattern', 'Unknown')}",
                "description": lambda issue: f"Server reveals sensitive information: {issue.get('description', '')}",
                "severity": lambda issue, default: Severity.MEDIUM if "password" in str(issue).lower() or "secret" in str(issue).lower() else default,
                "category": VulnerabilityCategory.INFORMATION_DISCLOSURE,
                "recommendations": [
                    "Sanitize error messages",
                    "Remove debug information from production",
                    "Implement proper logging practices"
                ]
            },
            {
                "matcher": lambda issue: issue.get("type") == "potentially_dangerous_tool",
                "title": lambda issue: f"Dangerous Tool Access: {issue.get('tool_name', 'Unknown')}",
                "description": lambda issue: f"Tool with dangerous capabilities is accessible: {issue.get('description', '')}",
                "severity": lambda issue, default: Severity.HIGH,
                "category": VulnerabilityCategory.AUTHORIZATION,
                "recommendations": [
                    "Implement proper access controls for dangerous tools",
                    "Require authentication for sensitive operations",
                    "Add audit logging for tool usage"
                ]
            },
            {
                "matcher": lambda issue: issue.get("type") == "unauthorized_tool_access",
                "title": lambda issue: "Authorization Bypass: Unauthorized Tool Access",
                "description": lambda issue: f"Tools can be accessed without proper authorization: {issue.get('description', '')}",
                "severity": lambda issue, default: Severity.HIGH,
                "category": VulnerabilityCategory.AUTHORIZATION,
                "recommendations": [
                    "Implement authentication checks for all tools",
                    "Use role-based access control",
                    "Add session validation"
                ]
            },
            {
                "matcher": lambda issue: issue.get("type") == "debug_information_leak",
                "title": lambda issue: f"Debug Information Exposure: {issue.get('key', 'Unknown')}",
                "description": lambda issue: f"Debug information exposed in responses: {issue.get('description', '')}",
                "severity": lambda issue, default: Severity.LOW,
                "category": VulnerabilityCategory.INFORMATION_DISCLOSURE,
                "recommendations": [
                    "Remove debug information from production builds",
                    "Implement proper error handling",
                    "Use structured logging"
                ]
            }
        ]
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO
        }
        return severity_map.get(severity_str.lower(), Severity.LOW)
    
    def _infer_category_from_type(self, issue_type: str) -> VulnerabilityCategory:
        """Infer vulnerability category from issue type."""
        category_keywords = {
            VulnerabilityCategory.AUTHENTICATION: ["auth", "login", "password", "token", "credential"],
            VulnerabilityCategory.AUTHORIZATION: ["access", "permission", "privilege", "bypass", "unauthorized"],
            VulnerabilityCategory.INPUT_VALIDATION: ["validation", "input", "parameter", "malformed"],
            VulnerabilityCategory.INFORMATION_DISCLOSURE: ["disclosure", "leak", "exposure", "information"],
            VulnerabilityCategory.PROTOCOL_VIOLATION: ["protocol", "violation", "format", "schema"],
            VulnerabilityCategory.DENIAL_OF_SERVICE: ["dos", "denial", "crash", "exhaustion", "limit"],
            VulnerabilityCategory.INJECTION: ["injection", "xss", "sql", "command", "script"],
            VulnerabilityCategory.SESSION_MANAGEMENT: ["session", "cookie", "state", "fixation"],
            VulnerabilityCategory.CRYPTOGRAPHY: ["crypto", "encryption", "hash", "signature", "certificate"]
        }
        
        issue_type_lower = issue_type.lower()
        
        for category, keywords in category_keywords.items():
            if any(keyword in issue_type_lower for keyword in keywords):
                return category
        
        return VulnerabilityCategory.CONFIGURATION  # Default category


class SecurityClassifier:
    """High-level security classification and risk assessment."""
    
    def __init__(self):
        self.risk_factors = {}
        self.compliance_checks = {}
    
    def classify_risk_level(self, findings: List[VulnerabilityFinding]) -> Tuple[str, Dict[str, Any]]:
        """Classify overall security risk level."""
        if not findings:
            return "low", {"reason": "No security vulnerabilities found"}
        
        # Count by severity
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        for finding in findings:
            severity_counts[finding.severity] += 1
        
        # Determine overall risk
        if severity_counts[Severity.CRITICAL] > 0:
            risk_level = "critical"
            reason = f"Found {severity_counts[Severity.CRITICAL]} critical vulnerabilities"
        elif severity_counts[Severity.HIGH] >= 3:
            risk_level = "high"  
            reason = f"Found {severity_counts[Severity.HIGH]} high severity vulnerabilities"
        elif severity_counts[Severity.HIGH] > 0:
            risk_level = "high"
            reason = f"Found {severity_counts[Severity.HIGH]} high severity vulnerabilities"
        elif severity_counts[Severity.MEDIUM] >= 5:
            risk_level = "medium"
            reason = f"Found {severity_counts[Severity.MEDIUM]} medium severity vulnerabilities"
        elif severity_counts[Severity.MEDIUM] > 0:
            risk_level = "medium"
            reason = f"Found {severity_counts[Severity.MEDIUM]} medium severity vulnerabilities"
        else:
            risk_level = "low"
            reason = f"Only low severity or informational findings ({severity_counts[Severity.LOW]} low, {severity_counts[Severity.INFO]} info)"
        
        risk_details = {
            "reason": reason,
            "severity_breakdown": {s.value: count for s, count in severity_counts.items()},
            "total_findings": len(findings),
            "most_common_categories": self._get_common_categories(findings)
        }
        
        return risk_level, risk_details
    
    def generate_executive_summary(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate executive summary of security assessment."""
        risk_level, risk_details = self.classify_risk_level(findings)
        
        # Get top vulnerabilities
        critical_high_findings = [
            f for f in findings 
            if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]
        
        # Compliance implications
        compliance_issues = self._assess_compliance_implications(findings)
        
        return {
            "overall_risk_level": risk_level,
            "total_vulnerabilities": len(findings),
            "severity_breakdown": risk_details["severity_breakdown"],
            "top_concerns": [f.title for f in critical_high_findings[:5]],
            "most_affected_categories": risk_details["most_common_categories"],
            "compliance_implications": compliance_issues,
            "recommended_actions": self._get_priority_actions(findings),
            "assessment_summary": self._generate_summary_text(risk_level, findings)
        }
    
    def _get_common_categories(self, findings: List[VulnerabilityFinding]) -> List[Tuple[str, int]]:
        """Get most common vulnerability categories."""
        category_counts = {}
        for finding in findings:
            cat = finding.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        return sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    
    def _assess_compliance_implications(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Assess compliance implications of findings."""
        implications = []
        
        categories = [f.category for f in findings]
        
        if VulnerabilityCategory.AUTHENTICATION in categories:
            implications.append("Authentication vulnerabilities may violate access control requirements")
        
        if VulnerabilityCategory.INFORMATION_DISCLOSURE in categories:
            implications.append("Data disclosure issues may violate privacy regulations")
        
        if VulnerabilityCategory.DENIAL_OF_SERVICE in categories:
            implications.append("Availability issues may impact service level agreements")
        
        # Check for high-severity findings
        high_severity = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if high_severity:
            implications.append("High severity vulnerabilities require immediate remediation")
        
        return implications
    
    def _get_priority_actions(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Get priority remediation actions."""
        actions = []
        
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            actions.append(f"Immediately address {len(critical_findings)} critical vulnerabilities")
        
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        if high_findings:
            actions.append(f"Prioritize remediation of {len(high_findings)} high severity issues")
        
        # Category-specific actions
        categories = [f.category for f in findings]
        if VulnerabilityCategory.AUTHENTICATION in categories:
            actions.append("Review and strengthen authentication mechanisms")
        
        if VulnerabilityCategory.DENIAL_OF_SERVICE in categories:
            actions.append("Implement rate limiting and resource protection")
        
        if VulnerabilityCategory.INFORMATION_DISCLOSURE in categories:
            actions.append("Audit information exposure and sanitize outputs")
        
        return actions[:5]  # Top 5 actions
    
    def _generate_summary_text(self, risk_level: str, findings: List[VulnerabilityFinding]) -> str:
        """Generate human-readable assessment summary."""
        if not findings:
            return "Security assessment completed with no vulnerabilities identified. The server appears to have good security posture."
        
        summary_templates = {
            "critical": f"CRITICAL security issues identified. Immediate action required. {len(findings)} total vulnerabilities found with critical impact on security posture.",
            "high": f"HIGH risk security issues discovered. Priority remediation needed. {len(findings)} vulnerabilities identified requiring urgent attention.",
            "medium": f"MEDIUM risk security concerns found. Planned remediation recommended. {len(findings)} vulnerabilities should be addressed in next maintenance cycle.",
            "low": f"LOW risk security findings identified. Standard remediation timeline acceptable. {len(findings)} minor issues found."
        }
        
        return summary_templates.get(risk_level, f"Security assessment completed. {len(findings)} findings require review.")