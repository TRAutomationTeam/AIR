import os
import json
from typing import Dict, List, Any
import logging
import re
from gpt4all import GPT4All

class AICodeAnalyzer:
    def __init__(self, config: dict = None, metrics: dict = None):
        self.config = config or {}
        self.metrics = metrics or {}
        model_path = os.path.join(os.path.dirname(__file__), "models", "ggml-gpt4all-j-v1.3-groovy.bin")
        
        # Initialize lightweight model for code review
        self.model = GPT4All(model_path)
        logging.info("Using GPT4All for code analysis")
        
    def _convert_analysis_results(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert analysis results to our expected format."""
        violations = []
        
        # Convert issues
        for idx, issue in enumerate(analysis.get('issues', [])):
            violations.append({
                'RuleId': f'AI-ISS-{idx:03d}',
                'RuleName': 'Code Issue',
                'Severity': issue.get('severity', 'Warning'),
                'Description': issue.get('description', ''),
                'Recommendation': 'Fix the identified issue',
                'Line': issue.get('line', '')
            })
            
        # Convert violations
        for idx, violation in enumerate(analysis.get('violations', [])):
            violations.append({
                'RuleId': f'AI-VIO-{idx:03d}',
                'RuleName': violation.get('rule', 'Best Practice Violation'),
                'Severity': 'Warning',
                'Description': violation.get('description', ''),
                'Recommendation': violation.get('recommendation', '')
            })
            
        # Convert security issues
        for idx, sec in enumerate(analysis.get('security', [])):
            violations.append({
                'RuleId': f'AI-SEC-{idx:03d}',
                'RuleName': 'Security Issue',
                'Severity': sec.get('severity', 'Error'),
                'Description': sec.get('description', ''),
                'Recommendation': sec.get('mitigation', '')
            })
            
        # Convert performance issues
        for idx, perf in enumerate(analysis.get('performance', [])):
            violations.append({
                'RuleId': f'AI-PERF-{idx:03d}',
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
        """Analyze workflow results using local GPT4All model"""
        logging.info("Starting local model analysis")

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

            # Prepare input for the model
            input_text = f"{prompt}\n\n{chr(10).join(prompt_lines)}"

            # Generate response using GPT4All
            logging.info("Generating analysis with local model")
            response = self.model.generate(
                input_text,
                max_tokens=2048,
                temp=0.7,
                top_p=0.95,
                n_predict=512,
                streaming=False
            )

            try:
                # Parse the LLM response
                analysis = json.loads(response)
                
                # Convert to our expected format
                return {
                    'enhanced_analysis': True,
                    'rules_violations': self._convert_analysis_results(analysis),
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
                logging.error(f"Failed to parse model response: {str(e)}")
                # Process response and extract meaningful insights
                try:
                    analysis = json.loads(response)
                except json.JSONDecodeError:
                    # If response is not valid JSON, try to extract meaningful content
                    analysis = self._extract_analysis_from_text(response)
                
                return {
                    'enhanced_analysis': True,
                    'rules_violations': self._convert_analysis_results(analysis),
                    'original_analysis': analysis_results,
                    'summary': {
                        'total_issues': len(analysis.get('issues', [])),
                        'total_violations': len(analysis.get('violations', [])),
                        'security_concerns': len(analysis.get('security', [])),
                        'performance_issues': len(analysis.get('performance', [])),
                        'quality_recommendations': len(analysis.get('quality', []))
                    }
                }

        except Exception as e:
            logging.error(f"Error during local model analysis: {str(e)}")
    def _extract_analysis_from_text(self, text: str) -> Dict[str, Any]:
        """Extract structured analysis from unstructured model output"""
        analysis = {
            'issues': [],
            'violations': [],
            'security': [],
            'performance': [],
            'quality': []
        }
        
        # Simple pattern matching to extract insights
        lines = text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            if line.lower().startswith('issue:'):
                current_section = 'issues'
                analysis['issues'].append({
                    'severity': 'Warning',
                    'description': line[6:].strip()
                })
            elif line.lower().startswith('security:'):
                current_section = 'security'
                analysis['security'].append({
                    'severity': 'Error',
                    'description': line[9:].strip()
                })
            elif line.lower().startswith('performance:'):
                current_section = 'performance'
                analysis['performance'].append({
                    'impact': 'Medium',
                    'description': line[12:].strip()
                })
                
        return analysis

    def _fallback_analysis(self, analysis_results: Dict) -> Dict:
        """Return local analysis results when AI analysis fails"""
        logging.info("Using fallback analysis (local results only)")
        return {
            'enhanced_analysis': False,
            'rules_violations': [],
            'original_analysis': analysis_results,
            'summary': {
                'total_issues': 0,
                'total_violations': 0,
                'security_concerns': 0,
                'performance_issues': 0,
                'quality_recommendations': 0
            }
        }