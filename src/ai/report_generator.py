import json
import logging
import os
import re
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
            'ai_status': analysis_results.get('ai_status', 'UNKNOWN'),
            'ai_error': analysis_results.get('ai_error'),
            'ai_provider': analysis_results.get('ai_provider', 'LiteLLM'),
            'ai_model': analysis_results.get('ai_model', ''),
            'next_steps': self._generate_next_steps({'go_no_go_decision': decision})
        }
        # Build structured AI recommendations table (Rule ID, Suggestion) if possible
        ai_rows = []
        ai_status = report_data.get('ai_status')
        if ai_status == 'SUCCESS' and report_data['ai_insights']:
            last_rule_id = None
            heading_pattern_primary = re.compile(r'^\*\*(.+?)\s*\(([^()]+)\)\*\*:?$', re.IGNORECASE)
            heading_pattern_alt = re.compile(r'^\*\*([^*]+)\*\*\s*\(([^()]+)\)')  # **Title** (RULE)
            inline_rule_pattern = re.compile(r'\b[A-Z]{2,}-[A-Z0-9]{2,}-\d{3}\b')
            suggestion_pattern = re.compile(r'^\*\*Suggestion\*\*:\s*(.+)$', re.IGNORECASE)
            actionable_starts = tuple(['add','ensure','remove','use','reduce','review','move','refactor','optimize','implement'])
            per_rule_added = {}
            for raw_line in report_data['ai_insights']:
                line = raw_line.strip()
                if not line:
                    continue
                # Skip generic closing / boilerplate
                low = line.lower()
                if low.startswith('ensure to address each of these') or low.startswith('these suggestions will'):
                    continue
                # Explicit suggestion line following a heading
                m_sug = suggestion_pattern.match(line)
                if m_sug and last_rule_id:
                    suggestion_text = m_sug.group(1).strip()
                    if last_rule_id not in per_rule_added:
                        ai_rows.append({'rule_id': last_rule_id, 'suggestion': suggestion_text})
                        per_rule_added[last_rule_id] = True
                    last_rule_id = None
                    continue
                # Heading styles
                m_head = heading_pattern_primary.match(line) or heading_pattern_alt.match(line)
                if m_head:
                    # Rule id expected inside parentheses (group 2)
                    rid_candidate = m_head.group(2).strip()
                    # Validate candidate has pattern
                    if inline_rule_pattern.search(rid_candidate):
                        last_rule_id = inline_rule_pattern.search(rid_candidate).group(0)
                        continue
                # Attempt to detect rule id inline even if not heading
                rid_inline_match = inline_rule_pattern.search(line)
                if rid_inline_match and ('suggestion' not in low):
                    last_rule_id = rid_inline_match.group(0)
                    # If line also seems actionable (contains a verb), we may treat rest as suggestion if colon present
                    continue
                # Plain actionable sentence: associate with last_rule_id if present
                if last_rule_id and low.startswith(actionable_starts):
                    if last_rule_id not in per_rule_added:
                        ai_rows.append({'rule_id': last_rule_id, 'suggestion': line})
                        per_rule_added[last_rule_id] = True
                    last_rule_id = None
                    continue
                # Fallback generic suggestion (only if looks actionable but no rule context)
                if low.startswith(actionable_starts):
                    ai_rows.append({'rule_id': 'GENERAL', 'suggestion': line})
            # Deduplicate while preserving order
            seen_combo = set()
            deduped = []
            for row in ai_rows:
                key = (row['rule_id'].lower(), row['suggestion'].lower())
                if key in seen_combo:
                    continue
                seen_combo.add(key)
                deduped.append(row)
            ai_rows = deduped
            # Second pass: infer rule IDs for GENERAL entries using keyword patterns
            if ai_rows:
                pattern_map = [
                    (re.compile(r'exception handling|trycatch', re.IGNORECASE), 'UI-DBP-006'),
                    (re.compile(r'logmessage|logging', re.IGNORECASE), 'UI-DBP-013'),
                    (re.compile(r'comments?\b', re.IGNORECASE), 'UI-DBP-007'),
                    (re.compile(r'hardcoded values?', re.IGNORECASE), 'UI-DBP-008'),
                    (re.compile(r'naming convention|naming', re.IGNORECASE), 'ST-NMG-001'),
                    (re.compile(r'unused variables?', re.IGNORECASE), 'ST-USG-002'),
                    (re.compile(r'activities? in each workflow', re.IGNORECASE), 'AT-WFC-002'),
                    (re.compile(r'number of workflows', re.IGNORECASE), 'AT-WFC-001'),
                    (re.compile(r'flow control', re.IGNORECASE), 'UI-DBP-018'),
                    (re.compile(r'delay times?|optimi[sz]e delay', re.IGNORECASE), 'UI-PRF-001'),
                    (re.compile(r'timeout values?', re.IGNORECASE), 'ST-DBP-021')
                ]
                for row in ai_rows:
                    if row['rule_id'] != 'GENERAL':
                        continue
                    text = row['suggestion']
                    for pat, rid in pattern_map:
                        if pat.search(text):
                            row['rule_id'] = rid
                            break
        report_data['ai_recommendations_table'] = ai_rows
        if report_data['ai_status'] == 'SUCCESS':
            logging.info(f"AI suggestions working: {len(report_data['ai_insights'])} suggestions.")
        elif report_data['ai_status'] == 'FALLBACK':
            logging.warning(f"AI fallback used. Error: {report_data.get('ai_error')}")
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
                """Generate the HTML report using a Jinja2 template."""
                html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>UiPath Code Review Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: linear-gradient(90deg,#4b9cd3 0%,#6dd5ed 100%); color:#fff; padding:28px 22px 20px; border-radius:12px; box-shadow:0 4px 16px rgba(75,156,211,0.15); margin-bottom:16px; }
        .header h1 { margin:0 0 6px; font-size:2.1em; }
        .summary { margin:20px 0; }
        .metrics { display:flex; gap:16px; margin:20px 0; }
        .metric { background:#e8f4f8; padding:12px 14px; border-radius:6px; flex:1; }
        table { border-collapse:collapse; width:100%; margin:20px 0; }
        th, td { border:1px solid #ddd; padding:6px 8px; text-align:left; }
        th { background:#f2f2f2; }
        .file-list { font-size:0.85em; margin:0; padding:0; list-style:none; }
        .file-list li { margin-bottom:2px; }
        .ai-insights { background:#f8f8ff; border-left:4px solid #4b9cd3; margin:20px 0; padding:12px 15px; border-radius:5px; }
        .ai-banner { padding:10px; border-radius:6px; margin:16px 0; font-size:0.95em; }
        .ai-banner.success { background:#e6f9f0; border:1px solid #2e8b57; color:#1e5a3a; }
        .ai-banner.fallback { background:#fff4e5; border:1px solid #e6a23c; color:#7c4a00; }
        .ai-banner.error { background:#ffecec; border:1px solid #ff6b6b; color:#7a0000; }
    </style>
</head>
<body>
    <div class="header">
        <h1>UiPath Code Review Report</h1>
        <p>Generated: <strong>{{ timestamp }}</strong></p>
        <p>Project: <strong>{{ project_info.name or 'Unknown' }}</strong></p>
    </div>
    <div class="summary">
        <h2>Summary</h2>
        {% set decision_val = go_no_go_decision or analysis_summary.decision %}
        <p><strong>Decision:</strong>
            {% if decision_val == 'GO' %}
                <span style="color:green;font-weight:bold;">GO</span>
            {% elif decision_val == 'NO_GO' %}
                <span style="color:red;font-weight:bold;">NO_GO</span>
            {% else %}
                <span style="color:#cc8800;font-weight:bold;">REVIEW_REQUIRED</span>
            {% endif %}
        </p>
        <p><strong>Quality Score:</strong> {{ analysis_summary.quality_score }}/100</p>
        <p><strong>Total Violations:</strong> {{ analysis_summary.total_violations }}</p>
        <p><strong>Critical Issues:</strong> {{ analysis_summary.critical_issues }}</p>
        <div class="ai-banner {% if ai_status == 'SUCCESS' %}success{% elif ai_status == 'FALLBACK' %}fallback{% else %}error{% endif %}">
            <strong>AI Engine:</strong> {{ ai_provider }}{% if ai_model %} (model: {{ ai_model }}){% endif %}<br/>
            <strong>Status:</strong> {{ ai_status }}
            {% if ai_status == 'SUCCESS' %}- {{ ai_insights|length }} recommendations generated.
            {% elif ai_status == 'FALLBACK' %}- Falling back to rule-based recommendations only.
            {% else %}- No AI data available.
            {% endif %}
            {% if ai_error %}<br/><strong>Last Error:</strong> {{ ai_error }}{% endif %}
        </div>
    </div>
    <div class="metrics">
        <div class="metric"><h3>Maintainability</h3><p>{{ quality_metrics.maintainability_score }}/100</p></div>
        <div class="metric"><h3>Reliability</h3><p>{{ quality_metrics.reliability_score }}/100</p></div>
        <div class="metric"><h3>Performance</h3><p>{{ quality_metrics.performance_score }}/100</p></div>
        <div class="metric"><h3>Security</h3><p>{{ quality_metrics.security_score }}/100</p></div>
    </div>
    {% set filtered_violations = detailed_results.original_analysis.rules_violations | selectattr('Severity','in',['Warning','Error']) | list %}
    {% if filtered_violations %}
    <div class="ai-insights">
        <h2>Rule-Based Suggestions (from static analyzer)</h2>
        <table><tr><th>#</th><th>Suggestion</th></tr>
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
    {% if filtered_violations %}
    <div class="violations">
        <h2>Rule Violations Summary</h2>
        {% set grouped = {} %}
        {% for v in filtered_violations %}
            {% set key = v.RuleId ~ '|' ~ v.RuleName ~ '|' ~ v.Severity %}
            {% set base_rec = v.RuleId == 'AT-WFC-002' and 'Reduce the number of activities in each workflow to improve maintainability.' or v.Recommendation.split(' has ')[0].split('Current count')[0].strip() %}
            {% if key not in grouped %}
                {% set _ = grouped.update({key:{'count':0,'files':[],'rule_id':v.RuleId,'rule_name':v.RuleName,'severity':v.Severity,'recommendation':base_rec}}) %}
            {% endif %}
            {% set _ = grouped[key].update({'count': grouped[key]['count'] + 1}) %}
            {% if v.get('FilePath') %}
                {% if v.FilePath not in grouped[key]['files'] %}{% set _ = grouped[key]['files'].append(v.FilePath) %}{% endif %}
            {% elif v.get('File') %}
                {% if v.File not in grouped[key]['files'] %}{% set _ = grouped[key]['files'].append(v.File) %}{% endif %}
            {% endif %}
        {% endfor %}
        {% set errors = [] %}
        {% set warnings = [] %}
        {% for key, data in grouped.items() %}
            {% if data.severity == 'Error' %}{% set _ = errors.append(data) %}{% else %}{% set _ = warnings.append(data) %}{% endif %}
        {% endfor %}
        <table><tr><th>Rule ID</th><th>Rule Name</th><th>Severity</th><th>Count</th><th>Recommendation</th><th>Files</th></tr>
        {% for data in errors|sort(attribute='rule_id') %}
        <tr style="background-color:#ffe6e6;"><td>{{ data.rule_id }}</td><td>{{ data.rule_name }}</td><td>{{ data.severity }}</td><td>{{ data.count }}</td><td>{{ data.recommendation }}</td><td><ul class='file-list'>{% for f in data.files %}<li>{{ f }}</li>{% endfor %}</ul></td></tr>
        {% endfor %}
        {% for data in warnings|sort(attribute='rule_id') %}
        <tr style="background-color:#fffbe6;"><td>{{ data.rule_id }}</td><td>{{ data.rule_name }}</td><td>{{ data.severity }}</td><td>{{ data.count }}</td><td>{{ data.recommendation }}</td><td><ul class='file-list'>{% for f in data.files %}<li>{{ f }}</li>{% endfor %}</ul></td></tr>
        {% endfor %}
        </table>
        <h2>AI Recommendations</h2>
        {% if ai_status == 'SUCCESS' and ai_recommendations_table %}
            <table><tr><th>Rule ID</th><th>AI Suggestion</th></tr>
            {% for row in ai_recommendations_table %}
                <tr><td>{{ row.rule_id }}</td><td>{{ row.suggestion }}</td></tr>
            {% endfor %}
            </table>
        {% elif ai_status == 'SUCCESS' and ai_insights %}
            <ul>{% for item in ai_insights %}<li>{{ item }}</li>{% endfor %}</ul>
        {% elif ai_status != 'SUCCESS' %}
            <p>No AI recommendations (status: {{ ai_status }}).</p>
        {% else %}
            <p>AI returned success but no recommendations parsed.</p>
        {% endif %}
    </div>
    {% endif %}
    <div class="next-steps">
        <h2>Next Steps</h2>
        <ul>{% for step in next_steps %}<li>{{ step }}</li>{% endfor %}</ul>
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
            'ai_insights': report_data.get('ai_insights', []),
            'ai_status': report_data.get('ai_status', 'UNKNOWN'),
            'ai_error': report_data.get('ai_error')
            ,'ai_provider': report_data.get('ai_provider'),
            'ai_model': report_data.get('ai_model')
        }