import requests
import yaml
import os
# Environment variable mapping (see README for details)
# AI_ARENA_API_KEY, AI_ARENA_ENDPOINT, AI_ARENA_MODEL_NAME
from typing import Dict, List, Any
import logging

class AICodeAnalyzer:
    def __init__(self, ai_endpoint: str = None, api_key: str = None, model_name: str = None):
        # Load AI Arena config from settings.txt
        config_path = os.path.join(os.path.dirname(__file__), '../../config/settings.txt')
        with open(config_path, 'r', encoding='utf-8') as f:
            settings = yaml.safe_load(f)
        ai_config = settings.get('ai_arena', {})
        self.ai_endpoint = ai_config.get('endpoint', ai_endpoint)
        self.api_key = ai_config.get('api_key', api_key)
        self.model_name = model_name or 'openai_gpt-4-turbo'
        
    def analyze_workflow_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Send workflow analyzer results to AI for enhanced analysis"""
        logging.info(f"[DEBUG] AI Endpoint: {self.ai_endpoint}")
        logging.info(f"[DEBUG] API Key (first 20 chars): {self.api_key[:20]}...")
        logging.info(f"[DEBUG] Model Name: {self.model_name}")
        workflow_id = "80f448d2-fd59-440f-ba24-ebc3014e1fdf"
        endpoint = f"{self.ai_endpoint.rstrip('/')}/v1/inference"
        payload = {
            "workflow_id": workflow_id,
            "query": "Run UiPath workflow analysis.",
            "is_persistence_allowed": False,
            "modelparams": {
                self.model_name: {
                    "system_prompt": "You are an experienced Software Developer. Respond in a professional manner.",
                    "temperature": "0.7",
                    "top_p": "0.9",
                    "frequency_penalty": "0",
                    "max_tokens": "800",
                    "presence_penalty": "0"
                }
            }
        }
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        try:
            logging.info(f"[DEBUG] Sending POST to {endpoint}")
            response = requests.post(
                endpoint,
                json=payload,
                headers=headers,
                timeout=120
            )
            logging.info(f"[DEBUG] Response status code: {response.status_code}")
            logging.info(f"[DEBUG] Response text: {response.text[:200]}...")
            if response.status_code == 200:
                ai_results = response.json()
                return self._process_ai_results(ai_results, analysis_results)
            else:
                logging.error(f"AI analysis failed: {response.status_code}")
                return self._fallback_analysis(analysis_results)
        except Exception as e:
            logging.error(f"Error calling AI service: {e}")
            return self._fallback_analysis(analysis_results)
            
    def _process_ai_results(self, ai_results: Dict, original_results: Dict) -> Dict[str, Any]:
        """Process AI analysis results"""
        
        return {
            'original_analysis': original_results,
            'ai_insights': ai_results.get('insights', []),
            'recommendations': ai_results.get('recommendations', []),
            'quality_score': ai_results.get('quality_score', 0),
            'go_no_go_decision': ai_results.get('decision', 'REVIEW_REQUIRED'),
            'confidence': ai_results.get('confidence', 0),
            'summary': ai_results.get('summary', ''),
            'critical_issues': ai_results.get('critical_issues', []),
            'improvement_suggestions': ai_results.get('improvements', [])
        }
        
    def _fallback_analysis(self, analysis_results: Dict) -> Dict[str, Any]:
        """Fallback analysis when AI is unavailable"""
        
        violations = analysis_results.get('rules_violations', [])
        
        # Simple rule-based scoring
        critical_count = len([v for v in violations if v.get('Severity') == 'Error'])
        warning_count = len([v for v in violations if v.get('Severity') == 'Warning'])
        
        quality_score = max(0, 100 - (critical_count * 20) - (warning_count * 5))
        
        if critical_count > 0:
            decision = 'NO_GO'
        elif quality_score >= 80:
            decision = 'GO'
        else:
            decision = 'REVIEW_REQUIRED'
            
        return {
            'original_analysis': analysis_results,
            'ai_insights': ['AI service unavailable - using rule-based analysis'],
            'recommendations': self._generate_basic_recommendations(violations),
            'quality_score': quality_score,
            'go_no_go_decision': decision,
            'confidence': 0.6,
            'summary': f'Found {critical_count} critical and {warning_count} warning issues',
            'critical_issues': [v for v in violations if v.get('Severity') == 'Error'],
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