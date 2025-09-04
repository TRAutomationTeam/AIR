import requests
import yaml
import os
import json
from typing import Dict, List, Any
import logging
import re

class AICodeAnalyzer:
    def __init__(self, ai_endpoint: str = None, api_key: str = None, model_name: str = None, config: dict = None, metrics: dict = None):
        self.ai_endpoint = ai_endpoint
        self.api_key = api_key
        self.model_name = model_name or 'openai_gpt-4-turbo'
        self.config = config or {}
        self.metrics = metrics or {}
        
    def analyze_workflow_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Send workflow analyzer results to AI for enhanced analysis with targeted suggestions"""
        workflow_id = "80f448d2-fd59-440f-ba24-ebc3014e1fdf"
        endpoint = f"{self.ai_endpoint.rstrip('/')}/v1/inference"
        logging.info(f"Making request to TR Arena API endpoint: {endpoint}")

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
            logging.debug(f"Request payload: {json.dumps(payload, indent=2)}")
            logging.debug(f"Request headers: Authorization: Bearer ***{self.api_key[-4:] if self.api_key else 'None'}")
            
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=120
            )
            
            logging.info(f"TR Arena API response status: {response.status_code}")
            
            if response.status_code == 200:
                logging.info("TR Arena API request successful")
                ai_results = response.json()
                logging.info("TR Arena API response received")
                logging.debug(f"API Response: {json.dumps(ai_results, indent=2)}")
                result = self._process_ai_results(ai_results, analysis_results)
                logging.info("TR Arena API results processed and combined with local analysis")
                
                # Process custom rules
                custom_rules = [rule for rule in self.config.get('official_rules', []) if rule.get('type') == 'custom']
                violations_list = result['original_analysis'].setdefault('rules_violations', [])
                
                for rule in custom_rules:
                    metric = rule.get('metric')
                    threshold = rule.get('threshold')
                    if metric and threshold is not None:
                        metric_value = analysis_results.get(metric, 0)
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
            
            logging.error(f"TR Arena API request failed with status {response.status_code}")
            logging.error(f"Response text: {response.text[:500]}...")
            return self._fallback_analysis(analysis_results)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error connecting to TR Arena API: {str(e)}")
            return self._fallback_analysis(analysis_results)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse TR Arena API response: {str(e)}")
            return self._fallback_analysis(analysis_results)
        except Exception as e:
            logging.error(f"Unexpected error in TR Arena API call: {str(e)}")
            return self._fallback_analysis(analysis_results)

    def _process_ai_results(self, ai_results: Dict, original_results: Dict) -> Dict[str, Any]:
        """Process AI analysis results and combine with original analysis"""
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
        model_data = answer.get(self.model_name, {}) if self.model_name in answer else answer

        def split_suggestions(text):
            if not isinstance(text, str):
                return text
            items = re.split(r'\n\s*\d+\.\s*', text)
            items = [i.strip() for i in items if i.strip()]
            if len(items) > 1:
                return items
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
            
            if isinstance(insights, str):
                insights = split_suggestions(insights)
            if isinstance(recommendations, str):
                recommendations = split_suggestions(recommendations)
            if isinstance(improvements, str):
                improvements = split_suggestions(improvements)
        elif isinstance(model_data, str):
            insights = split_suggestions(model_data)

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
            'critical_issues': critical_issues
        }

    def _fallback_analysis(self, analysis_results: Dict) -> Dict:
        """Return local analysis results when AI analysis fails"""
        logging.info("Using fallback analysis (local results only)")
        return {
            'original_analysis': analysis_results,
            'ai_insights': [],
            'recommendations': [],
            'quality_score': 0,
            'go_no_go_decision': 'REVIEW_REQUIRED',
            'confidence': 0,
            'summary': 'Analysis based on local rules only',
            'critical_issues': []
        }
