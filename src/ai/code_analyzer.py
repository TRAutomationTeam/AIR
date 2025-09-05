import requests
import yaml
import os
import json
from typing import Dict, List, Any
import logging
import re

class AICodeAnalyzer:
    def __init__(self, config: dict = None, metrics: dict = None):
        self.config = config or {}
        self.metrics = metrics or {}
        self.ollama_endpoint = "http://localhost:11434/api/generate"
        self.model = "codellama:7b-code"
        
    def _convert_ollama_results(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert Ollama analysis results to our expected format."""
        violations = []
        
        # Convert issues
        for idx, issue in enumerate(analysis.get('issues', [])):
            violations.append({
                'RuleId': f'OLLM-ISS-{idx:03d}',
                'RuleName': 'Code Issue',
                'Severity': issue.get('severity', 'Warning'),
                'Description': issue.get('description', ''),
                'Recommendation': 'Fix the identified issue',
                'Line': issue.get('line', '')
            })
            
        # Convert violations
        for idx, violation in enumerate(analysis.get('violations', [])):
            violations.append({
                'RuleId': f'OLLM-VIO-{idx:03d}',
                'RuleName': violation.get('rule', 'Best Practice Violation'),
                'Severity': 'Warning',
                'Description': violation.get('description', ''),
                'Recommendation': violation.get('recommendation', '')
            })
            
        # Convert security issues
        for idx, sec in enumerate(analysis.get('security', [])):
            violations.append({
                'RuleId': f'OLLM-SEC-{idx:03d}',
                'RuleName': 'Security Issue',
                'Severity': sec.get('severity', 'Error'),
                'Description': sec.get('description', ''),
                'Recommendation': sec.get('mitigation', '')
            })
            
        # Convert performance issues
        for idx, perf in enumerate(analysis.get('performance', [])):
            violations.append({
                'RuleId': f'OLLM-PERF-{idx:03d}',
                'RuleName': 'Performance Issue',
                'Severity': 'Warning' if perf.get('impact') == 'Low' else 'Error',
                'Description': perf.get('description', ''),
                'Recommendation': perf.get('solution', '')
            })
            
        return violations
        
    def _get_system_prompt(self) -> str:
        """Get system prompt for code analysis."""
        return """
        You are an expert UiPath code reviewer. Analyze the workflow and provide:
        1. List of issues found (with severity)
        2. Best practices violations
        3. Security concerns
        4. Performance improvements
        5. Code quality recommendations
        
        Format your response as JSON with the following structure:
        {
            "issues": [{"severity": "Error|Warning", "description": "...", "line": "..."}],
            "violations": [{"rule": "...", "description": "...", "recommendation": "..."}],
            "security": [{"severity": "...", "description": "...", "mitigation": "..."}],
            "performance": [{"impact": "High|Medium|Low", "description": "...", "solution": "..."}],
            "quality": [{"category": "...", "recommendation": "..."}]
        }
        """
        
    def analyze_workflow_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze workflow results using local Ollama instance"""
        logging.info("Starting Ollama-based analysis")

        try:
            # Prepare violations for analysis
            violations = analysis_results.get('rules_violations', [])
            if not violations:
                violations = analysis_results.get('original_analysis', {}).get('rules_violations', [])
            violations = [v for v in violations if v.get('Severity') in ('Warning', 'Error')]

            # Create analysis request
            prompt = self._get_system_prompt()
            prompt_lines = ["### Current Analysis Results:"]
            for v in violations:
                rule_id = v.get('RuleId', 'Unknown')
                rule_name = v.get('RuleName', '')
                severity = v.get('Severity', '')
                recommendation = v.get('Recommendation', '')
                file = v.get('File', v.get('FilePath', ''))
                prompt_lines.append(f"- [{severity}] {rule_id} ({rule_name}) in {file}: {recommendation}")

            # Create the Ollama request
            payload = {
                "model": self.model,
                "prompt": f"{prompt}\n\n{chr(10).join(prompt_lines)}",
                "stream": False,
                "temperature": 0.7,
                "top_p": 0.9,
                "max_tokens": 2000
            }

            # Make request to local Ollama
            logging.info("Sending request to Ollama")
            response = requests.post(self.ollama_endpoint, json=payload)

            if response.status_code == 200:
                logging.info("Ollama analysis completed successfully")
                result = response.json()
                
                try:
                    # Parse the LLM response
                    analysis = json.loads(result['response'])
                    
                    # Convert to our expected format
                    return {
                        'enhanced_analysis': True,
                        'rules_violations': self._convert_ollama_results(analysis),
                        'original_analysis': analysis_results,
                        'summary': {
                            'total_issues': len(analysis.get('issues', [])),
                            'total_violations': len(analysis.get('violations', [])),
                            'security_concerns': len(analysis.get('security', [])),
                            'performance_issues': len(analysis.get('performance', [])),
                            'quality_recommendations': len(analysis.get('quality', []))
                        }
                    }
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to parse Ollama response: {str(e)}")
                    return analysis_results
            else:
                logging.error(f"Ollama request failed with status {response.status_code}")
                return analysis_results

        except Exception as e:
            logging.error(f"Error during Ollama analysis: {str(e)}")
            return analysis_results

                
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
