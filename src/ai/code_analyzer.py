import requests
import yaml
import os
# Environment variable mapping (see README for details)
# AI_ARENA_API_KEY, AI_ARENA_ENDPOINT, AI_ARENA_MODEL_NAME
from typing import Dict, List, Any
import logging

class AICodeAnalyzer:
    def __init__(self, ai_endpoint: str = None, api_key: str = None, model_name: str = None, config: dict = None, metrics: dict = None):
        self.ai_endpoint = ai_endpoint
        self.api_key = api_key
        self.model_name = model_name or 'openai_gpt-4-turbo'
        self.config = config or {}
        self.metrics = metrics or {}
        
    def analyze_workflow_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Send workflow analyzer results to AI for enhanced analysis with targeted suggestions"""
        import pprint
        workflow_id = "80f448d2-fd59-440f-ba24-ebc3014e1fdf"
        endpoint = f"{self.ai_endpoint.rstrip('/')}/v1/inference"
        logging.info(f"Connecting to TR Arena API at {self.ai_endpoint}")

        # Prepare a detailed prompt listing all violations
        violations = analysis_results.get('rules_violations', [])
        if not violations:
            violations = analysis_results.get('original_analysis', {}).get('rules_violations', [])
        # Only include warnings and errors
        violations = [v for v in violations if v.get('Severity') in ('Warning', 'Error')]

        prompt_lines = [
            "You are an expert UiPath code reviewer. Here are the warnings and errors found in my UiPath workflows:",
            ""
        ]
        for v in violations:
            rule_id = v.get('RuleId', 'Unknown')
            rule_name = v.get('RuleName', '')
            severity = v.get('Severity', '')
            recommendation = v.get('Recommendation', '')
            file = v.get('File', v.get('FilePath', ''))
            prompt_lines.append(f"- [{severity}] {rule_id} ({rule_name}) in {file}: {recommendation}")
        prompt_lines.append("")
        prompt_lines.append("For each issue above, provide a specific, actionable suggestion to resolve it. Format your response as a numbered list, mapping each suggestion to the corresponding issue.")
        detailed_prompt = "\n".join(prompt_lines)

        payload = {
            "workflow_id": workflow_id,
            "query": detailed_prompt,
            "is_persistence_allowed": False,
            "modelparams": {
                self.model_name: {
                    "system_prompt": "You are an experienced Software Developer. Respond in a professional manner.",
                    "temperature": "0.7",
                    "top_p": "0.9",
                    "frequency_penalty": "0",
                    "max_tokens": "1200",
                    "presence_penalty": "0"
                }
            }
        }
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        try:
            # Suppressed all logging output
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=120
            )
            # Suppressed all logging output
            if response.status_code == 200:
                logging.info("TR Arena API request successful")
                ai_results = response.json()
                logging.info("TR Arena API response received")
                result = self._process_ai_results(ai_results, analysis_results)
                logging.info("TR Arena API results processed and combined with local analysis")
                # Always append custom rule violations if not present
                custom_rules = [rule for rule in self.config.get('official_rules', []) if rule.get('type') == 'custom']
                violations_list = result['original_analysis'].setdefault('rules_violations', [])
                for rule in custom_rules:
                    metric = rule.get('metric')
                    threshold = rule.get('threshold')
                    if metric and threshold is not None:
                        metric_value = analysis_results.get(metric, 0)
                        # Special handling for activities_count (dict of file_path -> count)
                        if metric == "activities_count" and isinstance(metric_value, dict):
                            for file_path, count in metric_value.items():
                                if count > threshold:
                                    if not any(v.get('RuleId') == rule['id'] and v.get('File') == file_path for v in violations_list):
                                        recommendation = f"{rule.get('recommendation', '')} {file_path} has {count} activities (Threshold: {threshold})"
                                        violations_list.append({
                                            'RuleId': rule['id'],
                                            'RuleName': rule.get('name', rule['id']),
                                            'Severity': rule.get('severity', 'Error'),
                                            'Recommendation': recommendation,
                                            'File': file_path,
                                            'FilePath': file_path,
                                            'Count': count
                                        })
                        elif isinstance(metric_value, (int, float)) and metric_value > threshold:
                            if not any(v.get('RuleId') == rule['id'] for v in violations_list):
                                recommendation = f"{rule.get('recommendation', '')} Current count: {metric_value} (Threshold: {threshold})"
                                violations_list.append({
                                    'RuleId': rule['id'],
                                    'RuleName': rule.get('name', rule['id']),
                                    'Severity': rule.get('severity', 'Error'),
                                    'Recommendation': recommendation,
                                    'File': '',
                                    'FilePath': '',
                                    'Count': metric_value
                                })
                return result
            else:
                # Suppressed all logging output
                return self._fallback_analysis(analysis_results)
        except Exception as e:
            # Suppressed all logging output
            return self._fallback_analysis(analysis_results)
            
    def _process_ai_results(self, ai_results: Dict, original_results: Dict) -> Dict[str, Any]:
        """Process AI analysis results and log full response for debugging"""
        import pprint
        # Suppressed all logging output

        # Try to extract suggestions from possible fields
        # Typical structure: {'result': {'answer': {model_name: ...}}}
        insights = []
        recommendations = []
        improvements = []
        quality_score = 0
        decision = 'REVIEW_REQUIRED'
        confidence = 0
        summary = ''
        critical_issues = []

        result = ai_results.get('result', {})
        answer = result.get('answer', {})
        # Try model-specific key first
        model_data = answer.get(self.model_name, {}) if self.model_name in answer else answer

        # Try to extract fields
        def split_suggestions(text):
            if not isinstance(text, str):
                return text
            # Split by numbered items or newlines
            import re
            # Try numbered list split first
            items = re.split(r'\n\s*\d+\.\s*', text)
            # Remove empty and strip
            items = [i.strip() for i in items if i.strip()]
            if len(items) > 1:
                return items
            # Fallback: split by newlines
            return [line.strip() for line in text.split('\n') if line.strip()]

        if isinstance(model_data, dict):
            insights = model_data.get('insights', [])
            recommendations = model_data.get('recommendations', [])
            improvements = model_data.get('improvements', [])
            quality_score = model_data.get('quality_score', 0)
            decision = model_data.get('decision', 'REVIEW_REQUIRED')
            confidence = model_data.get('confidence', 0)
            summary = model_data.get('summary', '')
            critical_issues = model_data.get('critical_issues', [])
            # If suggestions are in a single string, split into list
            if isinstance(insights, str):
                insights = split_suggestions(insights)
            if isinstance(recommendations, str):
                recommendations = split_suggestions(recommendations)
            if isinstance(improvements, str):
                improvements = split_suggestions(improvements)
        elif isinstance(model_data, str):
            # If only a string is returned, split into list
            insights = split_suggestions(model_data)

        # Fallback: check top-level keys if not found
        if not insights:
            insights = ai_results.get('insights', [])
            if isinstance(insights, str):
                insights = split_suggestions(insights)
        if not recommendations:
            recommendations = ai_results.get('recommendations', [])
            if isinstance(recommendations, str):
                recommendations = split_suggestions(recommendations)
        if not improvements:
            improvements = ai_results.get('improvements', [])
            if isinstance(improvements, str):
                improvements = split_suggestions(improvements)

        return {
            'original_analysis': original_results,
            'ai_insights': insights,
            'recommendations': recommendations,
            'quality_score': quality_score,
            'go_no_go_decision': decision,
            'confidence': confidence,
            'summary': summary,
            'critical_issues': critical_issues,
            'improvement_suggestions': improvements
        }
        
    def _fallback_analysis(self, analysis_results: Dict) -> Dict[str, Any]:
        """Fallback analysis when AI is unavailable"""
        
        violations = analysis_results.get('rules_violations', [])
        # Process all custom rules from settings.txt (config)
        for rule in self.config.get('official_rules', []):
            if rule.get('type', 'custom') == 'custom':
                metric = rule.get('metric')
                threshold = rule.get('threshold')
                if metric and threshold is not None:
                    metric_value = analysis_results.get(metric, 0)
                    if metric == "activities_count" and isinstance(metric_value, dict):
                        for file_path, count in metric_value.items():
                            if count > threshold:
                                violations.append({
                                    'RuleId': rule['id'],
                                    'RuleName': rule.get('name', rule['id']),
                                    'Severity': rule.get('severity', 'Error'),
                                    'Recommendation': rule.get('recommendation', ''),
                                    'File': file_path,
                                    'FilePath': file_path,
                                    'Count': count
                                })
                    elif isinstance(metric_value, (int, float)) and metric_value > threshold:
                        violations.append({
                            'RuleId': rule['id'],
                            'RuleName': rule.get('name', rule['id']),
                            'Severity': rule.get('severity', 'Error'),
                            'Recommendation': rule.get('recommendation', ''),
                            'File': '',
                            'FilePath': '',
                            'Count': metric_value
                        })
        
        # Simple rule-based scoring
        # Load thresholds from config
        quality_threshold = self.config.get('quality_threshold', 80)
        min_confidence = self.config.get('min_confidence', 0.7)
        auto_approve_threshold = self.config.get('auto_approve_threshold', 95)
        max_errors_for_go = self.config.get('max_errors_for_go', 0)
        critical_rules = set(self.config.get('critical_rules', []))

        critical_issues = [v for v in violations if v.get('RuleId') in critical_rules or v.get('Severity') == 'Error']
        critical_count = len(critical_issues)
        warning_count = len([v for v in violations if v.get('Severity') == 'Warning'])
        quality_score = max(0, 100 - (critical_count * 20) - (warning_count * 5))
        confidence = 0.6

        # Decision logic
        if quality_score >= auto_approve_threshold and confidence >= min_confidence and critical_count <= max_errors_for_go:
            decision = 'GO'
        elif critical_count > max_errors_for_go:
            decision = 'NO_GO'
        elif quality_score >= quality_threshold and confidence >= min_confidence:
            decision = 'GO'
        else:
            decision = 'REVIEW_REQUIRED'

        return {
            'original_analysis': analysis_results,
            'ai_insights': ['AI service unavailable - using rule-based analysis'],
            'recommendations': self._generate_basic_recommendations(violations),
            'quality_score': quality_score,
            'go_no_go_decision': decision,
            'confidence': confidence,
            'summary': f'Found {critical_count} critical and {warning_count} warning issues',
            'critical_issues': critical_issues,
            'improvement_suggestions': []
        }
        
    def _generate_basic_recommendations(self, violations: List[Dict]) -> List[str]:
        """Generate basic recommendations based on violations"""
        
        recommendations = []
        
        rule_counts = {}
        for violation in violations:
            rule_id = violation.get('RuleId', 'Unknown')
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
        for rule_id, count in rule_counts.items():
            if count > 1:
                recommendations.append(f"Multiple violations of rule {rule_id} detected ({count} instances)")
                
        return recommendations