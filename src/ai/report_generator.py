import json
import logging
import os
from datetime import datetime
from jinja2 import Template
from typing import Dict, Any, List

class ReportGenerator:
    def __init__(self, template_path: str = "templates/report_template.html", config: Dict = None, metrics: Dict = None):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        self.template_path = template_path
        self.config = config or {}
        self.metrics = metrics or {}

    def generate_report(self, analysis_results: Dict[str, Any], 
                       project_info: Dict[str, Any], repo_path: str = None) -> Dict[str, Any]:
        """Generate comprehensive code review report"""
        logging.info("Generating report data...")
        # Make all file paths relative to repo_path
        def make_relative(path):
            if repo_path and path:
                try:
                    return os.path.relpath(path, repo_path)
                except Exception:
                    return path
            return path

        # Update violations file paths (top-level)
        if 'rules_violations' in analysis_results:
            for v in analysis_results['rules_violations']:
                if 'FilePath' in v:
                    v['FilePath'] = make_relative(v['FilePath'])
                if 'File' in v:
                    v['File'] = make_relative(v['File'])
        if 'files_analyzed' in analysis_results:
            analysis_results['files_analyzed'] = [make_relative(f) for f in analysis_results['files_analyzed']]

        # Update violations file paths (nested original_analysis)
        if 'original_analysis' in analysis_results and 'rules_violations' in analysis_results['original_analysis']:
            for v in analysis_results['original_analysis']['rules_violations']:
                if 'FilePath' in v:
                    v['FilePath'] = make_relative(v['FilePath'])
                if 'File' in v:
                    v['File'] = make_relative(v['File'])
        if 'original_analysis' in analysis_results and 'files_analyzed' in analysis_results['original_analysis']:
            analysis_results['original_analysis']['files_analyzed'] = [make_relative(f) for f in analysis_results['original_analysis']['files_analyzed']]
        # Enforce thresholds from config
        quality_score = analysis_results.get('quality_score', 0)
        confidence = analysis_results.get('confidence', 0)
        min_conf = self.config.get('min_confidence', 0.7)
        quality_threshold = self.config.get('quality_threshold', 80)
        auto_approve_threshold = self.config.get('auto_approve_threshold', 95)
        max_errors_for_go = self.config.get('max_errors_for_go', 0)
        critical_rules = set(self.config.get('critical_rules', []))
        violations = analysis_results.get('original_analysis', {}).get('rules_violations', [])
        critical_issues = [v for v in violations if v.get('RuleId') in critical_rules or v.get('Severity') == 'Error']

        # Decision logic
        if quality_score >= auto_approve_threshold and confidence >= min_conf and len(critical_issues) <= max_errors_for_go:
            decision = 'GO'
        elif len(critical_issues) > max_errors_for_go:
            decision = 'NO_GO'
        elif quality_score >= quality_threshold and confidence >= min_conf:
            decision = 'GO'
        else:
            decision = 'REVIEW_REQUIRED'

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'project_info': project_info,
            'analysis_summary': self._create_summary(analysis_results),
            'detailed_results': analysis_results,
            'go_no_go_decision': decision,
            'quality_metrics': self._calculate_metrics(analysis_results),
            'recommendations': analysis_results.get('recommendations', []),
            'ai_insights': analysis_results.get('ai_insights', []),
            'next_steps': self._generate_next_steps({'go_no_go_decision': decision})
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
        # Only include warnings and errors
        violations = [v for v in original_analysis.get('rules_violations', []) if v.get('Severity') in ('Warning', 'Error')]

        # Group violations by rule
        rule_violations = {}
        for v in violations:
            rule_id = v.get('RuleId', '')
            if rule_id == 'AT-WFC-001':
                logging.info(f"[DEBUG] Including AT-WFC-001 in report summary: {v}")
            if rule_id not in rule_violations:
                rule_violations[rule_id] = {
                    'name': v.get('RuleName', ''),
                    'severity': v.get('Severity', ''),
                    'count': 0,
                    'recommendation': v.get('Recommendation', ''),
                    'files': set()
                }
            rule_violations[rule_id]['count'] += 1
            if 'File' in v:
                rule_violations[rule_id]['files'].add(v['File'])
            elif 'FilePath' in v:
                rule_violations[rule_id]['files'].add(v['FilePath'])

        summary = {
            'total_violations': len(violations),
            'critical_issues': len([v for v in violations if v.get('Severity') == 'Error']),
            'quality_score': analysis_results.get('quality_score', 0),
            'rule_violations': [
                {
                    'id': rule_id,
                    'name': info['name'],
                    'severity': info['severity'],
                    'count': info['count'],
                    'recommendation': info['recommendation'],
                    'files': sorted(list(info['files']))
                }
                for rule_id, info in rule_violations.items()
            ],
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
                .header {
                    background: linear-gradient(90deg, #4b9cd3 0%, #6dd5ed 100%);
                    color: #fff;
                    padding: 32px 24px 24px 24px;
                    border-radius: 12px;
                    box-shadow: 0 4px 16px rgba(75,156,211,0.15);
                    margin-bottom: 16px;
                    position: relative;
                }
                .header h1 {
                    font-size: 2.5em;
                    font-weight: 700;
                    margin-bottom: 8px;
                    letter-spacing: 1px;
                    text-shadow: 1px 2px 8px rgba(0,0,0,0.08);
                }
                .header p {
                    font-size: 1.15em;
                    margin: 4px 0;
                    font-weight: 400;
                    text-shadow: 1px 1px 6px rgba(0,0,0,0.05);
                }
                .summary { margin: 20px 0; }
                .metrics { display: flex; gap: 20px; margin: 20px 0; }
                .metric { background-color: #e8f4f8; padding: 15px; border-radius: 5px; flex: 1; }
                .decision-go { color: green; font-weight: bold; }
                .decision-no-go { color: red; font-weight: bold; }
                .decision-review { color: red; font-weight: bold; }
                .violations { margin: 20px 0; }
                table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr.violation-warning { background-color: #fffbe6; }
                tr.violation-error { background-color: #ffe6e6; }
                .file-list { font-size: 0.95em; color: #555; margin: 0; padding: 0; list-style: none; }
                .file-list li { margin-bottom: 2px; }
                .ai-insights { background-color: #f8f8ff; border-left: 4px solid #4b9cd3; margin: 20px 0; padding: 15px; border-radius: 5px; }
                .ai-insights h2 { color: #4b9cd3; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>UiPath Code Review Report</h1>
                <p>Generated: <span style="font-weight:600;">{{ timestamp }}</span></p>
                <p>Project: <span style="font-weight:600;">{{ project_info.name or 'Unknown' }}</span></p>
            </div>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Decision:</strong> 
                    {% if analysis_summary.decision == 'REVIEW_REQUIRED' %}
                        <span style="color:red;font-weight:bold;">REVIEW_REQUIRED</span>
                    {% elif analysis_summary.decision == 'GO' %}
                        <span style="color:green;font-weight:bold;">GO</span>
                    {% else %}
                        <span style="color:red;font-weight:bold;">NO_GO</span>
                    {% endif %}
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
            {% set filtered_violations = detailed_results.original_analysis.rules_violations | selectattr('Severity', 'in', ['Warning', 'Error']) | list %}
            {% if filtered_violations %}
            <div class="ai-insights">
                <h2>TR AI Suggestions</h2>
                <table style="width:100%; border-collapse: collapse;">
                    <tr style="background-color:#f2f2f2;"><th>#</th><th>Suggestion</th></tr>
                    {% set seen_rules = [] %}
                    {% set suggestion_count = namespace(value=1) %}
                    {% for v in filtered_violations %}
                        {% set base_rec = v.RuleId == 'AT-WFC-002' and 'Reduce the number of activities in each workflow to improve maintainability.' or v.Recommendation.split(' has ')[0].split('Current count')[0].strip() %}
                        {% if v.RuleId not in seen_rules and base_rec %}
                            <tr><td>{{ suggestion_count.value }}.</td><td>{{ base_rec }}</td></tr>
                            {% set _ = seen_rules.append(v.RuleId) %}
                            {% set suggestion_count.value = suggestion_count.value + 1 %}
                        {% endif %}
                    {% endfor %}
                </table>
            </div>
            {% endif %}
            {% set filtered_violations = detailed_results.original_analysis.rules_violations | selectattr('Severity', 'in', ['Warning', 'Error']) | list %}
            {% if filtered_violations %}
            <div class="violations">
                <h2>Rule Violations Summary</h2>
                {% set grouped = {} %}
                {% for v in filtered_violations %}
                    {% set key = v.RuleId ~ '|' ~ v.RuleName ~ '|' ~ v.Severity %}
                    {% set base_rec = v.RuleId == 'AT-WFC-002' and 'Reduce the number of activities in each workflow to improve maintainability.' or v.Recommendation.split(' has ')[0].split('Current count')[0].strip() %}
                    {% if key not in grouped %}
                        {% set _ = grouped.update({key: {'count': 0, 'files': [], 'rule_id': v.RuleId, 'rule_name': v.RuleName, 'severity': v.Severity, 'recommendation': base_rec}}) %}
                    {% endif %}
                    {% set _ = grouped[key].update({'count': grouped[key]['count'] + 1}) %}
                    {% if v.get('FilePath') %}
                        {% if v.FilePath not in grouped[key]['files'] %}
                            {% set _ = grouped[key]['files'].append(v.FilePath) %}
                        {% endif %}
                    {% elif v.get('File') %}
                        {% if v.File not in grouped[key]['files'] %}
                            {% set _ = grouped[key]['files'].append(v.File) %}
                        {% endif %}
                    {% endif %}
                {% endfor %}
                {% set errors = [] %}
                {% set warnings = [] %}
                {% for key, data in grouped.items() %}
                    {% if data.severity == 'Error' %}
                        {% set _ = errors.append(data) %}
                    {% else %}
                        {% set _ = warnings.append(data) %}
                    {% endif %}
                {% endfor %}
                <table>
                    <tr><th>Rule ID</th><th>Rule Name</th><th>Severity</th><th>Count</th><th>Recommendation</th><th>Files</th></tr>
                    {% for data in errors|sort(attribute='rule_id') %}
                        <tr style="background-color:#ffe6e6;">
                            <td>{{ data.rule_id }}</td>
                            <td>{{ data.rule_name }}</td>
                            <td>{{ data.severity }}</td>
                            <td>{{ data.count }}</td>
                            <td>{{ data.recommendation }}</td>
                            <td><ul class="file-list">{% for f in data.files %}<li>{{ f }}</li>{% endfor %}</ul></td>
                        </tr>
                    {% endfor %}
                    {% for data in warnings|sort(attribute='rule_id') %}
                        <tr style="background-color:#fffbe6;">
                            <td>{{ data.rule_id }}</td>
                            <td>{{ data.rule_name }}</td>
                            <td>{{ data.severity }}</td>
                            <td>{{ data.count }}</td>
                            <td>{{ data.recommendation }}</td>
                            <td><ul class="file-list">{% for f in data.files %}<li>{{ f }}</li>{% endfor %}</ul></td>
                        </tr>
                    {% endfor %}
                </table>
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
        # Only include warnings and errors in JSON output
        repo_path = report_data['project_info'].get('repo_path') if 'project_info' in report_data else None
        def make_relative(path):
            if repo_path and path:
                try:
                    return os.path.relpath(path, repo_path)
                except Exception:
                    return path
            return path
        filtered_violations = [v.copy() for v in report_data['detailed_results']['original_analysis'].get('rules_violations', []) if v.get('Severity') in ('Warning', 'Error')]
        for v in filtered_violations:
            if 'FilePath' in v:
                v['FilePath'] = make_relative(v['FilePath'])
            if 'File' in v:
                v['File'] = make_relative(v['File'])
        return {
            'decision': report_data['go_no_go_decision'],
            'quality_score': report_data['analysis_summary']['quality_score'],
            'total_violations': report_data['analysis_summary']['total_violations'],
            'critical_issues': report_data['analysis_summary']['critical_issues'],
            'confidence': report_data['detailed_results'].get('confidence', 0),
            'summary': report_data['detailed_results'].get('summary', ''),
            'recommendations_count': len(report_data['recommendations']),
            'timestamp': report_data['timestamp'],
            'violations': filtered_violations,
            'recommendations': report_data.get('recommendations', []),
            'ai_insights': report_data.get('ai_insights', [])
        }