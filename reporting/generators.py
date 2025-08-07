"""
Report generation orchestration.
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.analyzers import VulnAnalyzer, SecurityClassifier


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate comprehensive security assessment reports."""
    
    def __init__(self):
        self.vuln_analyzer = VulnAnalyzer()
        self.security_classifier = SecurityClassifier()
    
    def generate_comprehensive_report(
        self, 
        client_summary: Dict[str, Any],
        security_issues: List[Dict[str, Any]] = None,
        protocol_violations: List[Any] = None,
        stress_results: List[Any] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive security assessment report."""
        logger.info("Generating comprehensive security report")
        
        try:
            # Analyze all security findings
            all_findings = []
            
            if security_issues:
                findings = self.vuln_analyzer.analyze_security_issues(security_issues)
                all_findings.extend(findings)
            
            if protocol_violations:
                findings = self.vuln_analyzer.analyze_protocol_violations(protocol_violations)
                all_findings.extend(findings)
            
            if stress_results:
                findings = self.vuln_analyzer.analyze_stress_test_results(stress_results)
                all_findings.extend(findings)
            
            # Generate executive summary
            executive_summary = self.security_classifier.generate_executive_summary(all_findings)
            
            # Build comprehensive report
            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "mcpred",
                    "version": "0.1.0"
                },
                "target_info": {
                    "url": client_summary.get("target", "Unknown"),
                    "transport_type": client_summary.get("transport_type", "Unknown"),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "executive_summary": executive_summary,
                "vulnerabilities": [finding.to_dict() for finding in all_findings],
                "server_capabilities": client_summary.get("capabilities", {}),
                "test_results": self._generate_test_results_summary(
                    client_summary, 
                    security_issues, 
                    protocol_violations, 
                    stress_results
                ),
                "raw_data": {
                    "client_summary": client_summary,
                    "security_issues": security_issues or [],
                    "protocol_violations": [
                        v.to_dict() if hasattr(v, 'to_dict') else v 
                        for v in (protocol_violations or [])
                    ],
                    "stress_results": [
                        r.to_dict() if hasattr(r, 'to_dict') else r 
                        for r in (stress_results or [])
                    ]
                }
            }
            
            logger.info(f"Generated report with {len(all_findings)} findings")
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
    
    def generate_executive_summary_only(
        self,
        client_summary: Dict[str, Any],
        security_issues: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate executive summary report only."""
        logger.info("Generating executive summary report")
        
        try:
            # Analyze security issues
            all_findings = []
            if security_issues:
                all_findings = self.vuln_analyzer.analyze_security_issues(security_issues)
            
            executive_summary = self.security_classifier.generate_executive_summary(all_findings)
            
            return {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "mcpred",
                    "version": "0.1.0",
                    "report_type": "executive_summary"
                },
                "target_info": {
                    "url": client_summary.get("target", "Unknown"),
                    "transport_type": client_summary.get("transport_type", "Unknown"),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "executive_summary": executive_summary
            }
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            raise
    
    def generate_findings_report(
        self,
        vulnerabilities: List[Any],
        include_raw: bool = False
    ) -> Dict[str, Any]:
        """Generate detailed findings report."""
        logger.info("Generating detailed findings report")
        
        try:
            # Convert vulnerabilities to findings if needed
            if vulnerabilities and hasattr(vulnerabilities[0], 'to_dict'):
                findings_data = [v.to_dict() for v in vulnerabilities]
            else:
                findings_data = vulnerabilities or []
            
            # Calculate summary statistics
            severity_counts = {}
            category_counts = {}
            
            for finding in findings_data:
                severity = finding.get("severity", "unknown")
                category = finding.get("category", "unknown")
                
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                category_counts[category] = category_counts.get(category, 0) + 1
            
            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "mcpred",
                    "version": "0.1.0",
                    "report_type": "findings"
                },
                "findings_summary": {
                    "total_findings": len(findings_data),
                    "severity_breakdown": severity_counts,
                    "category_breakdown": category_counts
                },
                "vulnerabilities": findings_data
            }
            
            if include_raw:
                report["raw_data"] = {
                    "original_vulnerabilities": vulnerabilities
                }
            
            return report
            
        except Exception as e:
            logger.error(f"Findings report generation failed: {e}")
            raise
    
    def _generate_test_results_summary(
        self,
        client_summary: Dict[str, Any],
        security_issues: List[Dict[str, Any]],
        protocol_violations: List[Any],
        stress_results: List[Any]
    ) -> Dict[str, Any]:
        """Generate test results summary section."""
        
        summary = {}
        
        # Discovery results
        capabilities = client_summary.get("capabilities")
        if capabilities:
            summary["discovery"] = {
                "status": "completed",
                "capabilities_found": (
                    len(capabilities.get("tools", [])) +
                    len(capabilities.get("resources", [])) +
                    len(capabilities.get("prompts", []))
                ),
                "tools_found": len(capabilities.get("tools", [])),
                "resources_found": len(capabilities.get("resources", [])),
                "prompts_found": len(capabilities.get("prompts", []))
            }
        
        # Authentication test results
        if security_issues:
            auth_issues = [
                issue for issue in security_issues
                if issue.get("type", "").startswith("auth") or 
                   "authentication" in issue.get("description", "").lower()
            ]
            summary["authentication"] = {
                "status": "completed",
                "total_tests": len(security_issues),
                "vulnerabilities_found": len(auth_issues),
                "issues": auth_issues
            }
        
        # Protocol fuzzing results
        if protocol_violations:
            summary["protocol_fuzzing"] = {
                "status": "completed",
                "total_tests": len(protocol_violations),
                "violations_found": len([v for v in protocol_violations if self._is_successful_violation(v)]),
                "violation_types": list(set(
                    self._get_violation_type(v) for v in protocol_violations
                ))
            }
        
        # Stress testing results
        if stress_results:
            successful_stress = [r for r in stress_results if self._is_successful_stress_result(r)]
            summary["stress_testing"] = {
                "status": "completed",
                "total_tests": len(stress_results),
                "vulnerabilities_found": len(successful_stress),
                "test_types": list(set(
                    self._get_stress_test_type(r) for r in stress_results
                ))
            }
        
        # Overall assessment status
        total_issues = (
            len(security_issues or []) +
            len([v for v in (protocol_violations or []) if self._is_successful_violation(v)]) +
            len([r for r in (stress_results or []) if self._is_successful_stress_result(r)])
        )
        
        summary["overall"] = {
            "status": "completed",
            "total_vulnerabilities": total_issues,
            "assessment_complete": True
        }
        
        return summary
    
    def _is_successful_violation(self, violation: Any) -> bool:
        """Check if protocol violation indicates a successful test (vulnerability found)."""
        if hasattr(violation, 'success'):
            return violation.success
        elif isinstance(violation, dict):
            return violation.get("success", False)
        else:
            return False
    
    def _get_violation_type(self, violation: Any) -> str:
        """Get violation type from violation object."""
        if hasattr(violation, 'type'):
            return violation.type
        elif isinstance(violation, dict):
            return violation.get("type", "unknown")
        else:
            return "unknown"
    
    def _is_successful_stress_result(self, result: Any) -> bool:
        """Check if stress test result indicates a vulnerability."""
        if hasattr(result, 'success'):
            return result.success
        elif isinstance(result, dict):
            return result.get("success", False)
        else:
            return False
    
    def _get_stress_test_type(self, result: Any) -> str:
        """Get stress test type from result object."""
        if hasattr(result, 'test_type'):
            return result.test_type
        elif isinstance(result, dict):
            return result.get("test_type", "unknown")
        else:
            return "unknown"