import requests

import yaml
import os
import json
from typing import Dict, List, Any
import logging
import re
import getpass

# Load LiteLLM API config from settings.txt
def load_litellm_config(settings_path: str = os.path.join(os.path.dirname(__file__), '../config/settings.txt')):
    api_key = None
    api_url = None
    try:
        with open(settings_path, 'r') as f:
            for line in f:
                if line.strip().startswith('litellm_api_key:'):
                    api_key = line.split(':', 1)[1].strip()
                if line.strip().startswith('litellm_api_url:'):
                    api_url = line.split(':', 1)[1].strip()
    except Exception as e:
        logging.error(f"Error loading LiteLLM config: {e}")
    return api_key, api_url



class AICodeAnalyzer:
    def __init__(self, config: dict = None, metrics: dict = None):
        self.config = config or {}
        self.metrics = metrics or {}
        
    def analyze_workflow_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use LiteLLM for enhanced analysis and AI suggestions"""
        violations = analysis_results.get('rules_violations', [])
        if not violations:
            violations = analysis_results.get('original_analysis', {}).get('rules_violations', [])
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

        # Load LiteLLM API config
        api_key, api_url = load_litellm_config()
        if not api_key or not api_url:
            logging.error("LiteLLM API key or URL not found in settings.txt")
            return self._fallback_analysis(analysis_results)

            import time
            max_retries = 3
            for attempt in range(1, max_retries + 1):
                try:
                    payload = {
                        "prompt": detailed_prompt,
                        "model": "gpt-3.5-turbo",  # or the model you want to use
                        "temperature": 0.2
                    }
                    headers = {
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    }
                    logging.info(f"[LiteLLM API] Endpoint: {api_url}")
                    logging.info(f"[LiteLLM API] Payload: {json.dumps(payload)}")
                    response = requests.post(api_url, headers=headers, json=payload, timeout=60)
                    logging.info(f"[LiteLLM API] Response status: {response.status_code}")
                    logging.info(f"[LiteLLM API] Response headers: {response.headers}")
                    logging.info(f"[LiteLLM API] Response body: {response.text}")
                    if response.status_code == 200:
                        try:
                            data = response.json()
                        except Exception as e:
                            logging.error(f"[LiteLLM API] JSON decode error: {e}")
                            return self._fallback_analysis(analysis_results)
                        # Validate expected response structure
                        choices = data.get("choices")
                        if not choices or not isinstance(choices, list):
                            logging.error(f"[LiteLLM API] Unexpected response format: {data}")
                            return self._fallback_analysis(analysis_results)
                        answer = choices[0].get("message", {}).get("content", "")
                        if not answer:
                            logging.error(f"[LiteLLM API] No content in response: {data}")
                            return self._fallback_analysis(analysis_results)
                        suggestions = [line.strip() for line in answer.split('\n') if line.strip()]
                        return {
                            'original_analysis': analysis_results,
                            'ai_insights': suggestions,
                            'recommendations': suggestions,
                            'quality_score': 0,
                            'go_no_go_decision': 'REVIEW_REQUIRED',
                            'confidence': 0,
                            'summary': 'AI suggestions generated by LiteLLM',
                            'critical_issues': []
                        }
                    else:
                        logging.error(f"[LiteLLM API] Call failed (status {response.status_code}): {response.text}")
                        # Retry on server error (5xx), else fallback
                        if 500 <= response.status_code < 600 and attempt < max_retries:
                            logging.info(f"Retrying API call (attempt {attempt + 1})...")
                            time.sleep(2 * attempt)
                            continue
                        return self._fallback_analysis(analysis_results)
                except Exception as e:
                    logging.error(f"[LiteLLM API] Exception: {str(e)} (attempt {attempt})")
                    if attempt < max_retries:
                        logging.info(f"Retrying API call (attempt {attempt + 1})...")
                        time.sleep(2 * attempt)
                        continue
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
