"""
Output formatting for security reports.
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class BaseFormatter(ABC):
    """Base class for report formatters."""
    
    @abstractmethod
    def format_report(self, report_data: Dict[str, Any]) -> str:
        """Format report data to string output."""
        pass
    
    @abstractmethod
    def get_file_extension(self) -> str:
        """Get file extension for this format."""
        pass


class JSONFormatter(BaseFormatter):
    """JSON report formatter."""
    
    def __init__(self, indent: int = 2):
        self.indent = indent
    
    def format_report(self, report_data: Dict[str, Any]) -> str:
        """Format report data as JSON."""
        try:
            return json.dumps(report_data, indent=self.indent, default=self._json_serializer)
        except Exception as e:
            logger.error(f"JSON formatting failed: {e}")
            raise
    
    def get_file_extension(self) -> str:
        """Get JSON file extension."""
        return ".json"
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)


class TextFormatter(BaseFormatter):
    """Plain text report formatter."""
    
    def __init__(self, width: int = 80):
        self.width = width
    
    def format_report(self, report_data: Dict[str, Any]) -> str:
        """Format report data as plain text."""
        try:
            output = []
            
            # Header
            output.append("=" * self.width)
            output.append("MCPRED SECURITY ASSESSMENT REPORT")
            output.append("=" * self.width)
            output.append("")
            
            # Executive Summary
            if "executive_summary" in report_data:
                output.append("EXECUTIVE SUMMARY")
                output.append("-" * 20)
                summary = report_data["executive_summary"]
                output.append(f"Overall Risk Level: {summary.get('overall_risk_level', 'Unknown').upper()}")
                output.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                output.append("")
                
                if summary.get("assessment_summary"):
                    output.append(self._wrap_text(summary["assessment_summary"]))
                    output.append("")
            
            # Target Information
            if "target_info" in report_data:
                output.append("TARGET INFORMATION")
                output.append("-" * 20)
                target = report_data["target_info"]
                output.append(f"Target: {target.get('url', 'Unknown')}")
                output.append(f"Transport: {target.get('transport_type', 'Unknown')}")
                if target.get("timestamp"):
                    output.append(f"Assessed: {target['timestamp']}")
                output.append("")
            
            # Vulnerability Findings
            if "vulnerabilities" in report_data:
                output.append("VULNERABILITY FINDINGS")
                output.append("-" * 25)
                
                vulnerabilities = report_data["vulnerabilities"]
                if vulnerabilities:
                    for i, vuln in enumerate(vulnerabilities, 1):
                        output.append(f"{i}. {vuln.get('title', 'Unknown Vulnerability')}")
                        output.append(f"   Severity: {vuln.get('severity', 'Unknown').upper()}")
                        output.append(f"   Category: {vuln.get('category', 'Unknown')}")
                        
                        if vuln.get("description"):
                            output.append(f"   Description: {self._wrap_text(vuln['description'], indent=3)}")
                        
                        if vuln.get("recommendations"):
                            output.append("   Recommendations:")
                            for rec in vuln["recommendations"]:
                                output.append(f"   - {self._wrap_text(rec, indent=5)}")
                        
                        output.append("")
                else:
                    output.append("No vulnerabilities found.")
                    output.append("")
            
            # Server Capabilities
            if "server_capabilities" in report_data:
                caps = report_data["server_capabilities"]
                output.append("SERVER CAPABILITIES")
                output.append("-" * 20)
                
                if caps.get("tools"):
                    output.append(f"Tools Found: {len(caps['tools'])}")
                    for tool in caps["tools"][:5]:  # Show first 5
                        output.append(f"  - {tool.get('name', 'Unknown')}")
                    if len(caps["tools"]) > 5:
                        output.append(f"  ... and {len(caps['tools']) - 5} more")
                
                if caps.get("resources"):
                    output.append(f"Resources Found: {len(caps['resources'])}")
                    for resource in caps["resources"][:5]:  # Show first 5
                        output.append(f"  - {resource.get('name', 'Unknown')}")
                    if len(caps["resources"]) > 5:
                        output.append(f"  ... and {len(caps['resources']) - 5} more")
                
                output.append("")
            
            # Test Results Summary
            if "test_results" in report_data:
                results = report_data["test_results"]
                output.append("TEST RESULTS SUMMARY")
                output.append("-" * 22)
                
                if "discovery" in results:
                    discovery = results["discovery"]
                    output.append(f"Discovery: {discovery.get('status', 'Unknown')}")
                    if discovery.get("capabilities_found"):
                        output.append(f"  Capabilities Found: {discovery['capabilities_found']}")
                
                if "authentication" in results:
                    auth = results["authentication"]
                    output.append(f"Authentication Tests: {auth.get('total_tests', 0)} run, {auth.get('vulnerabilities_found', 0)} issues found")
                
                if "protocol_fuzzing" in results:
                    fuzz = results["protocol_fuzzing"]
                    output.append(f"Protocol Fuzzing: {fuzz.get('total_tests', 0)} tests, {fuzz.get('violations_found', 0)} violations")
                
                if "stress_testing" in results:
                    stress = results["stress_testing"]
                    output.append(f"Stress Testing: {stress.get('total_tests', 0)} tests, {stress.get('vulnerabilities_found', 0)} issues")
                
                output.append("")
            
            # Footer
            output.append("=" * self.width)
            output.append(f"Report generated by mcpred at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            output.append("=" * self.width)
            
            return "\n".join(output)
            
        except Exception as e:
            logger.error(f"Text formatting failed: {e}")
            raise
    
    def get_file_extension(self) -> str:
        """Get text file extension."""
        return ".txt"
    
    def _wrap_text(self, text: str, width: Optional[int] = None, indent: int = 0) -> str:
        """Wrap text to specified width with optional indentation."""
        if width is None:
            width = self.width - indent
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        indent_str = " " * indent
        
        for word in words:
            if current_length + len(word) + 1 > width:
                if current_line:
                    lines.append(indent_str + " ".join(current_line))
                    current_line = [word]
                    current_length = len(word)
                else:
                    # Word is longer than line width
                    lines.append(indent_str + word)
                    current_length = 0
            else:
                current_line.append(word)
                current_length += len(word) + (1 if current_line else 0)
        
        if current_line:
            lines.append(indent_str + " ".join(current_line))
        
        return "\n".join(lines)


class HTMLFormatter(BaseFormatter):
    """HTML report formatter."""
    
    def __init__(self, title: str = "Security Assessment Report"):
        self.title = title
    
    def format_report(self, report_data: Dict[str, Any]) -> str:
        """Format report data as HTML."""
        try:
            html_parts = []
            
            # HTML header
            html_parts.append(self._generate_html_header())
            
            # Executive summary
            if "executive_summary" in report_data:
                html_parts.append(self._generate_executive_summary(report_data["executive_summary"]))
            
            # Target information
            if "target_info" in report_data:
                html_parts.append(self._generate_target_info(report_data["target_info"]))
            
            # Vulnerability findings
            if "vulnerabilities" in report_data:
                html_parts.append(self._generate_vulnerabilities_section(report_data["vulnerabilities"]))
            
            # Server capabilities
            if "server_capabilities" in report_data:
                html_parts.append(self._generate_capabilities_section(report_data["server_capabilities"]))
            
            # Test results
            if "test_results" in report_data:
                html_parts.append(self._generate_test_results_section(report_data["test_results"]))
            
            # HTML footer
            html_parts.append(self._generate_html_footer())
            
            return "\n".join(html_parts)
            
        except Exception as e:
            logger.error(f"HTML formatting failed: {e}")
            raise
    
    def get_file_extension(self) -> str:
        """Get HTML file extension."""
        return ".html"
    
    def _generate_html_header(self) -> str:
        """Generate HTML document header with CSS."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #333;
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .risk-level {{
            padding: 10px;
            border-radius: 5px;
            font-weight: bold;
            text-align: center;
            margin: 10px 0;
        }}
        .risk-critical {{ background-color: #ffebee; color: #c62828; }}
        .risk-high {{ background-color: #fff3e0; color: #ef6c00; }}
        .risk-medium {{ background-color: #fff8e1; color: #f57f17; }}
        .risk-low {{ background-color: #e8f5e8; color: #2e7d32; }}
        .vulnerability {{
            border: 1px solid #ddd;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
        }}
        .vulnerability h3 {{
            margin-top: 0;
        }}
        .severity-critical {{ border-left: 5px solid #c62828; }}
        .severity-high {{ border-left: 5px solid #ef6c00; }}
        .severity-medium {{ border-left: 5px solid #f57f17; }}
        .severity-low {{ border-left: 5px solid #2e7d32; }}
        .severity-info {{ border-left: 5px solid #1976d2; }}
        .recommendations {{
            background-color: #f9f9f9;
            padding: 10px;
            border-radius: 3px;
            margin-top: 10px;
        }}
        .capabilities-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .capability-section {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Generated by mcpred</p>
        </div>"""
    
    def _generate_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Generate executive summary HTML section."""
        risk_level = summary.get("overall_risk_level", "unknown")
        risk_class = f"risk-{risk_level}"
        
        html = f"""
        <section>
            <h2>Executive Summary</h2>
            <div class="risk-level {risk_class}">
                Overall Risk Level: {risk_level.upper()}
            </div>
            <p><strong>Total Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)}</p>
            
            <h3>Severity Breakdown</h3>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>"""
        
        for severity, count in summary.get("severity_breakdown", {}).items():
            html += f"<tr><td>{severity.title()}</td><td>{count}</td></tr>"
        
        html += "</table>"
        
        if summary.get("assessment_summary"):
            html += f"<p>{summary['assessment_summary']}</p>"
        
        if summary.get("recommended_actions"):
            html += "<h3>Priority Actions</h3><ul>"
            for action in summary["recommended_actions"]:
                html += f"<li>{action}</li>"
            html += "</ul>"
        
        html += "</section>"
        return html
    
    def _generate_target_info(self, target_info: Dict[str, Any]) -> str:
        """Generate target information HTML section."""
        return f"""
        <section>
            <h2>Target Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Target URL</td><td>{target_info.get('url', 'Unknown')}</td></tr>
                <tr><td>Transport Type</td><td>{target_info.get('transport_type', 'Unknown')}</td></tr>
                <tr><td>Assessment Date</td><td>{target_info.get('timestamp', 'Unknown')}</td></tr>
            </table>
        </section>"""
    
    def _generate_vulnerabilities_section(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate vulnerabilities HTML section."""
        if not vulnerabilities:
            return """
            <section>
                <h2>Vulnerability Findings</h2>
                <p>No vulnerabilities were identified during the assessment.</p>
            </section>"""
        
        html = f"""
        <section>
            <h2>Vulnerability Findings ({len(vulnerabilities)} total)</h2>"""
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            severity_class = f"severity-{severity}"
            
            html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln.get('title', 'Unknown Vulnerability')}</h3>
                <p><strong>Severity:</strong> <span class="severity-{severity}">{severity.upper()}</span></p>
                <p><strong>Category:</strong> {vuln.get('category', 'Unknown')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>"""
            
            if vuln.get("recommendations"):
                html += '<div class="recommendations"><h4>Recommendations:</h4><ul>'
                for rec in vuln["recommendations"]:
                    html += f"<li>{rec}</li>"
                html += "</ul></div>"
            
            html += "</div>"
        
        html += "</section>"
        return html
    
    def _generate_capabilities_section(self, capabilities: Dict[str, Any]) -> str:
        """Generate server capabilities HTML section."""
        html = """
        <section>
            <h2>Server Capabilities</h2>
            <div class="capabilities-grid">"""
        
        if capabilities.get("tools"):
            html += f"""
            <div class="capability-section">
                <h3>Tools ({len(capabilities['tools'])})</h3>
                <ul>"""
            for tool in capabilities["tools"][:10]:  # Show first 10
                html += f"<li><strong>{tool.get('name', 'Unknown')}</strong> - {tool.get('description', 'No description')}</li>"
            if len(capabilities["tools"]) > 10:
                html += f"<li>... and {len(capabilities['tools']) - 10} more</li>"
            html += "</ul></div>"
        
        if capabilities.get("resources"):
            html += f"""
            <div class="capability-section">
                <h3>Resources ({len(capabilities['resources'])})</h3>
                <ul>"""
            for resource in capabilities["resources"][:10]:  # Show first 10
                html += f"<li><strong>{resource.get('name', 'Unknown')}</strong> - {resource.get('uri', 'No URI')}</li>"
            if len(capabilities["resources"]) > 10:
                html += f"<li>... and {len(capabilities['resources']) - 10} more</li>"
            html += "</ul></div>"
        
        if capabilities.get("prompts"):
            html += f"""
            <div class="capability-section">
                <h3>Prompts ({len(capabilities['prompts'])})</h3>
                <ul>"""
            for prompt in capabilities["prompts"][:10]:  # Show first 10
                html += f"<li><strong>{prompt.get('name', 'Unknown')}</strong> - {prompt.get('description', 'No description')}</li>"
            if len(capabilities["prompts"]) > 10:
                html += f"<li>... and {len(capabilities['prompts']) - 10} more</li>"
            html += "</ul></div>"
        
        html += "</div></section>"
        return html
    
    def _generate_test_results_section(self, test_results: Dict[str, Any]) -> str:
        """Generate test results HTML section."""
        html = """
        <section>
            <h2>Test Results Summary</h2>
            <table>
                <tr><th>Test Type</th><th>Status</th><th>Details</th></tr>"""
        
        for test_type, results in test_results.items():
            status = results.get("status", "Unknown")
            details = results.get("summary", "No details available")
            html += f"<tr><td>{test_type.title()}</td><td>{status}</td><td>{details}</td></tr>"
        
        html += "</table></section>"
        return html
    
    def _generate_html_footer(self) -> str:
        """Generate HTML document footer."""
        return f"""
        <div class="footer">
            <p>Report generated by mcpred on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""