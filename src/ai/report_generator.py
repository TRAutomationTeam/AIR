import json
import logging
from datetime import datetime
from jinja2 import Template
from typing import Dict, Any, List

class ReportGenerator:
    def __init__(self, template_path: str = "templates/report_template.html"):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        self.template_path = template_path
        
    def generate_report(self, analysis_results: Dict[str, Any], 
                       project_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive code review report"""
        logging.info("Generating report data...")
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'project_info': project_info,
            'analysis_summary': self._create_summary(analysis_results),
            'detailed_results': analysis_results,
            'go_no_go_decision': analysis_results.get('go_no_go_decision', 'REVIEW_REQUIRED'),
            'quality_metrics': self._calculate_metrics(analysis_results),
            'recommendations': analysis_results.get('recommendations', []),
            'next_steps': self._generate_next_steps(analysis_results)
        }
        logging.info("Generating HTML report...")
        html_report = self._generate_html_report(report_data)
        logging.info("Generating JSON summary...")
        json_summary = self._generate_json_summary(report_data)
        logging.info("Report generation complete.")
        return {
            'html_report': html_report,
            'json_summary': json_summary,
            'report_data': report_data
        }
        
    def _create_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create analysis summary"""
        
        original_analysis = analysis_results.get('original_analysis', {})
        violations = original_analysis.get('rules_violations', [])
        
        summary = {
            'total_violations': len(violations),
            'critical_issues': len(analysis_results.get('critical_issues', [])),
            'quality_score': analysis_results.get('quality_score', 0),
            'files_analyzed': len(original_analysis.get('files_analyzed', [])),
            'decision': analysis_results.get('go_no_go_decision', 'REVIEW_REQUIRED'),
            'confidence': analysis_results.get('confidence', 0)
        }
        
        # Categorize violations by severity
        severity_counts = {}
        for violation in violations:
            severity = violation.get('Severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        summary['severity_breakdown'] = severity_counts
        
        return summary
        
    def _calculate_metrics(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate quality metrics"""
        
        return {
            'maintainability_score': self._calculate_maintainability(analysis_results),
            'reliability_score': self._calculate_reliability(analysis_results),
            'performance_score': self._calculate_performance(analysis_results),
            'security_score': self._calculate_security(analysis_results)
        }
        
    def _calculate_maintainability(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate maintainability score"""
        base_score = 100
        violations = analysis_results.get('original_analysis', {}).get('rules_violations', [])
        
        # Deduct points for maintainability-related violations
        maintainability_rules = ['ST001', 'ST003', 'ST004']  # Example rules
        
        for violation in violations:
            if violation.get('RuleId') in maintainability_rules:
                base_score -= 5
                
        return max(0, base_score)
        
    def _calculate_reliability(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate reliability score"""
        base_score = 100
        critical_issues = analysis_results.get('critical_issues', [])
        
        # Deduct more points for critical issues
        base_score -= len(critical_issues) * 15
        
        return max(0, base_score)
        
    def _calculate_performance(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate performance score"""
        # Implement performance-related scoring
        return 85  # Placeholder
        
    def _calculate_security(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate security score"""
        # Implement security-related scoring
        return 90  # Placeholder
        
    def _generate_next_steps(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate next steps based on analysis"""
        
        decision = analysis_results.get('go_no_go_decision', 'REVIEW_REQUIRED')
        next_steps = []
        
        if decision == 'GO':
            next_steps.append("✅ Code review passed - Ready for deployment")
            next_steps.append("Consider implementing suggested improvements for future iterations")
            
        elif decision == 'NO_GO':
            next_steps.append("❌ Code review failed - Address critical issues before deployment")
            next_steps.append("Focus on resolving error-level violations first")
            next_steps.append("Re-run analysis after fixes are implemented")
            
        else:  # REVIEW_REQUIRED
            next_steps.append("⚠️ Manual review required")
            next_steps.append("Review AI recommendations and decide on next steps")
            next_steps.append("Consider addressing warning-level violations")
            
        return next_steps
        
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report using template"""
        
        # Simple HTML template (you can make this more sophisticated)
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>UiPath Code Review Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
                .summary { margin: 20px 0; }
                .metrics { display: flex; gap: 20px; margin: 20px 0; }
                .metric { background-color: #e8f4f8; padding: 15px; border-radius: 5px; flex: 1; }
                .decision-go { color: green; font-weight: bold; }
                .decision-no-go { color: red; font-weight: bold; }
                .decision-review { color: orange; font-weight: bold; }
                .violations { margin: 20px 0; }
                .violation { margin: 10px 0; padding: 10px; border-left: 3px solid #ccc; }
                .violation-error { border-left-color: red; }
                .violation-warning { border-left-color: orange; }
                .violation-info { border-left-color: blue; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>UiPath Code Review Report</h1>
                <p>Generated: {{ timestamp }}</p>
                <p>Project: {{ project_info.name or 'Unknown' }}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Decision:</strong> 
                    <span class="decision-{{ analysis_summary.decision.lower().replace('_', '-') }}">
                        {{ analysis_summary.decision }}
                    </span>
                </p>
                <p><strong>Quality Score:</strong> {{ analysis_summary.quality_score }}/100</p>
                <p><strong>Total Violations:</strong> {{ analysis_summary.total_violations }}</p>
                <p><strong>Critical Issues:</strong> {{ analysis_summary.critical_issues }}</p>
            </div>
            
            <div class="metrics">
                <div class="metric">
                    <h3>Maintainability</h3>
                    <p>{{ quality_metrics.maintainability_score }}/100</p>
                </div>
                <div class="metric">
                    <h3>Reliability</h3>
                    <p>{{ quality_metrics.reliability_score }}/100</p>
                </div>
                <div class="metric">
                    <h3>Performance</h3>
                    <p>{{ quality_metrics.performance_score }}/100</p>
                </div>
                <div class="metric">
                    <h3>Security</h3>
                    <p>{{ quality_metrics.security_score }}/100</p>
                </div>
            </div>
            
            {% if detailed_results.original_analysis.rules_violations %}
            <div class="violations">
                <h2>Critical Errors & Important Rules</h2>
                <table>
                    <tr>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Severity</th>
                        <th>File</th>
                        <th>Description</th>
                        <th>Recommendation</th>
                    </tr>
                    {% for violation in detailed_results.original_analysis.rules_violations if violation.Severity == 'Error' or violation.RuleId in ['PJ000','PJ001','XAML004'] %}
                    <tr class="violation-{{ violation.Severity.lower() }}">
                        <td>{{ violation.RuleId }}</td>
                        <td>{{ violation.RuleName }}</td>
                        <td>{{ violation.Severity }}</td>
                        <td>{{ violation.FilePath or 'Unknown' }}</td>
                        <td>{{ violation.Description or violation.ErrorsDescription or 'No description available' }}</td>
                        <td>{{ violation.Recommendation or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </table>
                <h2>All Rule Violations</h2>
                <table>
                    <tr>
                        <th>Rule ID</th>
                        <th>Rule Name</th>
                        <th>Severity</th>
                        <th>File</th>
                        <th>Description</th>
                        <th>Recommendation</th>
                    </tr>
                    {% for violation in detailed_results.original_analysis.rules_violations %}
                    <tr class="violation-{{ violation.Severity.lower() }}">
                        <td>{{ violation.RuleId }}</td>
                        <td>{{ violation.RuleName }}</td>
                        <td>{{ violation.Severity }}</td>
                        <td>{{ violation.FilePath or 'Unknown' }}</td>
                        <td>{{ violation.Description or violation.ErrorsDescription or 'No description available' }}</td>
                        <td>{{ violation.Recommendation or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            {% endif %}
            {% if recommendations %}
            <div class="recommendations">
                <h2>AI Recommendations</h2>
                <ul>
                {% for recommendation in recommendations %}
                    <li>{{ recommendation }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            <div class="next-steps">
                <h2>Next Steps</h2>
                <ul>
                {% for step in next_steps %}
                    <li>{{ step }}</li>
                {% endfor %}
                </ul>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        return template.render(**report_data)

        
    def _generate_json_summary(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JSON summary for API responses"""
        
        return {
            'decision': report_data['go_no_go_decision'],
            'quality_score': report_data['analysis_summary']['quality_score'],
            'total_violations': report_data['analysis_summary']['total_violations'],
            'critical_issues': report_data['analysis_summary']['critical_issues'],
            'confidence': report_data['detailed_results'].get('confidence', 0),
            'summary': report_data['detailed_results'].get('summary', ''),
            'recommendations_count': len(report_data['recommendations']),
            'timestamp': report_data['timestamp'],
            'violations': report_data['detailed_results']['original_analysis'].get('rules_violations', []),
            'recommendations': report_data.get('recommendations', [])
        }