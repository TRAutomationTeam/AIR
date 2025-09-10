import requests
import yaml
import os
import json
from typing import Dict, List, Any
import logging
import re
import getpass

_LITELLM_SETTINGS_CACHE: dict | None = None

def load_litellm_config(settings_path: str = os.path.join(os.path.dirname(__file__), '../config/settings.txt')):
    """Load LiteLLM configuration with caching, env overrides and sanitation."""
    global _LITELLM_SETTINGS_CACHE
    if _LITELLM_SETTINGS_CACHE is None:
        cfg = {}
        try:
            with open(settings_path, 'r', encoding='utf-8') as f:
                # Attempt YAML parse first (settings.txt is YAML-like)
                try:
                    cfg = yaml.safe_load(f) or {}
                except Exception:
                    f.seek(0)
                    for line in f:
                        ls = line.strip()
                        if ':' in ls:
                            k, v = ls.split(':', 1)
                            cfg[k.strip()] = v.strip()
        except Exception as e:
            logging.error(f"Failed reading LiteLLM config: {e}")
        _LITELLM_SETTINGS_CACHE = cfg
    cfg = dict(_LITELLM_SETTINGS_CACHE)

    # Environment overrides take precedence
    api_key = os.environ.get('LITELLM_API_KEY') or cfg.get('litellm_api_key')
    api_url = os.environ.get('LITELLM_API_URL') or cfg.get('litellm_api_url')
    model = os.environ.get('LITELLM_MODEL') or cfg.get('litellm_model') or 'gpt-3.5-turbo'
    try:
        temperature = float(os.environ.get('LITELLM_TEMPERATURE', cfg.get('litellm_temperature', 0.2)))
    except Exception:
        temperature = 0.2
    # Sanitize copy artifacts
    if isinstance(api_key, str):
        api_key = api_key.strip()
        if api_key.endswith('Copy'):
            logging.info("[LiteLLM] Stripping 'Copy' suffix from API key.")
            api_key = api_key[:-4]
    return api_key, api_url, model, temperature


class AICodeAnalyzer:
    def __init__(self, config: dict = None, metrics: dict = None):
        self.config = config or {}
        self.metrics = metrics or {}
        self._resolved_endpoint = None  # cache successful endpoint
        
    def analyze_workflow_results(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Use LiteLLM API for enhanced analysis and AI suggestions"""
        violations = analysis_results.get('rules_violations', [])
        if not violations:
            violations = analysis_results.get('original_analysis', {}).get('rules_violations', [])
        # Determine severities to include (config override) default Warning+Error
        include_sev = self.config.get('ai_include_severities') or ['Warning', 'Error']
        violations = [v for v in violations if v.get('Severity') in include_sev]
        # Force at least one item so AI call still executes (helps surface suggestions)
        if not violations:
            violations = [{
                'RuleId': 'DUMMY',
                'RuleName': 'No Violations Found',
                'Severity': 'Warning',
                'Recommendation': 'Project currently has no rule violations. Consider adding more best-practice checks.',
                'File': 'N/A'
            }]

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

        # Call LiteLLM API for AI suggestions
        api_key, api_url, model, temperature = load_litellm_config()
        if not api_key or not api_url:
            logging.error("LiteLLM API key or URL missing in settings.txt (litellm_api_key / litellm_api_url). Using fallback analysis.")
            return self._fallback_analysis(analysis_results)
        # Model/temperature override from instance config if provided
        model = self.config.get('litellm_model', model)
        if 'litellm_temperature' in self.config:
            try:
                temperature = float(self.config['litellm_temperature'])
            except Exception:
                pass

        try:
            # Determine candidate endpoints (support chat & completion styles) with caching of resolved endpoint
            if self._resolved_endpoint:
                candidate_urls = [self._resolved_endpoint]
            else:
                base = api_url.rstrip('/')
                if any(seg in base for seg in ("/chat/completions", "/v1/chat/completions", "/v1/completions")):
                    candidate_urls = [base]
                else:
                    candidate_urls = [
                        base + suffix for suffix in (
                            "/v1/chat/completions",
                            "/chat/completions",
                            "/v1/completions",
                            ""  # raw base last
                        )
                    ]

            masked_key = api_key[:6] + "***" + api_key[-4:] if len(api_key) > 10 else "***"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            }

            last_error = None
            for idx, endpoint in enumerate(candidate_urls, start=1):
                # Prefer chat schema payload first
                chat_payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are an expert UiPath code reviewer."},
                        {"role": "user", "content": detailed_prompt}
                    ],
                    "temperature": temperature
                }
                # Fallback completion style payload
                completion_payload = {
                    "model": model,
                    "prompt": detailed_prompt,
                    "temperature": temperature
                }
                for style, payload in (('chat', chat_payload), ('completion', completion_payload)):
                    logging.info(f"[LiteLLM] Attempt {idx}:{style} -> {endpoint}")
                    try:
                        response = requests.post(endpoint, headers=headers, json=payload, timeout=60)
                    except Exception as call_exc:
                        last_error = f"Request exception: {call_exc}"
                        logging.warning(f"[LiteLLM] {last_error}")
                        continue
                    logging.info(f"[LiteLLM] Status {response.status_code} for {endpoint} ({style})")
                    if response.status_code == 405:
                        # Method not allowed: try next endpoint variant
                        last_error = f"405 at {endpoint} ({style})"
                        continue
                    if response.status_code != 200:
                        last_error = f"{response.status_code} {response.text[:300]}"
                        continue
                    # Parse success
                    try:
                        data = response.json()
                        # Some proxies return 200 with embedded error object
                        if isinstance(data, dict) and 'error' in data:
                            err = data.get('error', {})
                            msg = err.get('message') if isinstance(err, dict) else str(err)
                            code = err.get('code') if isinstance(err, dict) else 'unknown'
                            logging.warning(f"[LiteLLM] Embedded error (HTTP 200) code={code} message={msg}")
                            last_error = f"embedded_error:{code}"
                            continue
                    except Exception as ejson:
                        # Attempt SSE (Server-Sent Events) style parsing
                        raw_text = response.text or ''
                        sse_content_collected = []
                        if 'data:' in raw_text:
                            for line in raw_text.splitlines():
                                if not line.startswith('data:'):
                                    continue
                                payload_part = line[len('data:'):].strip()
                                if not payload_part or payload_part == '[DONE]':
                                    continue
                                try:
                                    j = json.loads(payload_part)
                                except Exception:
                                    continue
                                # OpenAI-like chunk
                                choices_chunk = j.get('choices')
                                if isinstance(choices_chunk, list):
                                    for ch in choices_chunk:
                                        # Chat delta
                                        delta = ch.get('delta') or {}
                                        if isinstance(delta, dict):
                                            frag = delta.get('content')
                                            if isinstance(frag, str):
                                                sse_content_collected.append(frag)
                                        # Legacy text
                                        text_frag = ch.get('text')
                                        if isinstance(text_frag, str):
                                            sse_content_collected.append(text_frag)
                                # Some providers put "content" at top-level
                                top_content = j.get('content')
                                if isinstance(top_content, str):
                                    sse_content_collected.append(top_content)
                        if sse_content_collected:
                            combined = ''.join(sse_content_collected).strip()
                            if combined:
                                suggestions = [ln.strip() for ln in combined.split('\n') if ln.strip()]
                                logging.info(f"[LiteLLM] Parsed SSE stream content length={len(combined)} suggestions={len(suggestions)}")
                                return {
                                    'original_analysis': analysis_results,
                                    'ai_insights': suggestions,
                                    'recommendations': suggestions,
                                    'quality_score': 0,
                                    'go_no_go_decision': 'REVIEW_REQUIRED',
                                    'confidence': 0,
                                    'summary': 'AI suggestions generated by LiteLLM (SSE)',
                                    'critical_issues': []
                                }
                        last_error = f"JSON decode error: {ejson}"
                        logging.error(f"[LiteLLM] {last_error}")
                        snippet = raw_text[:800]
                        logging.info(f"[LiteLLM] Raw body snippet (JSON/SSE fail): {snippet}")
                        continue
                    # Extract answer: chat format or completion format
                    answer = ''
                    if 'choices' in data and isinstance(data['choices'], list) and data['choices']:
                        choice0 = data['choices'][0]
                        # 1. OpenAI chat format
                        answer = ''
                        msg_obj = choice0.get('message', {}) or {}
                        content_val = msg_obj.get('content')
                        if isinstance(content_val, list):
                            # list of segments or dict objects
                            segments = []
                            for seg in content_val:
                                if isinstance(seg, str):
                                    segments.append(seg)
                                elif isinstance(seg, dict):
                                    # common keys: text, content, value
                                    for k in ('text', 'content', 'value'):
                                        if isinstance(seg.get(k), str):
                                            segments.append(seg[k])
                                            break
                            answer = '\n'.join(s for s in segments if s)
                        elif isinstance(content_val, str):
                            answer = content_val
                        # 2. Legacy text completion
                        if not answer:
                            answer = choice0.get('text', '') or ''
                        # 3. Some providers embed messages list
                        if not answer and isinstance(choice0.get('messages'), list):
                            for msg in reversed(choice0['messages']):
                                if isinstance(msg, dict):
                                    c = msg.get('content')
                                    if isinstance(c, list):
                                        parts = []
                                        for p in c:
                                            if isinstance(p, str):
                                                parts.append(p)
                                            elif isinstance(p, dict):
                                                for k in ('text','content','value'):
                                                    if isinstance(p.get(k), str):
                                                        parts.append(p[k])
                                                        break
                                        if parts:
                                            answer = '\n'.join(parts)
                                            break
                                    elif isinstance(c, str):
                                        answer = c
                                        break
                        # 4. Direct content field
                        if not answer and 'content' in choice0 and isinstance(choice0['content'], str):
                            answer = choice0['content']
                        # 5. Streaming style aggregated under 'delta'
                        if not answer and choice0.get('delta') and isinstance(choice0['delta'], dict):
                            answer = choice0['delta'].get('content', '') or ''
                        # 6. Provider specific fields
                        if not answer:
                            for alt_key in ('output_text','answer','result','generated_text'):
                                if isinstance(choice0.get(alt_key), str) and choice0.get(alt_key).strip():
                                    answer = choice0.get(alt_key)
                                    break
                    # 6. Provider-specific top-level field fallbacks
                    if not answer:
                        answer = data.get('output') or data.get('response') or ''
                    if not answer:
                        snippet = (response.text or str(data))[:800]
                        logging.info(f"[LiteLLM] 200 body but no answer extracted. Keys={list(data.keys())} snippet={snippet}")
                        last_error = f"No answer content in response schema"
                        continue
                    suggestions = [line.strip() for line in answer.split('\n') if line.strip()]
                    logging.info(
                        f"[LiteLLM] AI suggestions active: {len(suggestions)} items (model={model}, temp={temperature})"
                    )
                    for i, s in enumerate(suggestions[:5], 1):
                        logging.debug(f"[LiteLLM] Suggestion {i}: {s[:180]}")
                    logging.info(f"[LiteLLM] Success via {endpoint} style={style} key={masked_key}")
                    # Cache successful endpoint
                    if not self._resolved_endpoint:
                        self._resolved_endpoint = endpoint
                    return {
                        'original_analysis': analysis_results,
                        'ai_insights': suggestions,
                        'recommendations': suggestions,
                        'ai_status': 'SUCCESS',
                        'quality_score': 0,
                        'go_no_go_decision': 'REVIEW_REQUIRED',
                        'confidence': 0,
                        'summary': 'AI suggestions generated by LiteLLM',
                        'critical_issues': []
                    }
            logging.error(f"[LiteLLM] All attempts failed. Last error: {last_error}")
            return self._fallback_analysis(analysis_results, ai_error=last_error)
        except Exception as e:
            logging.error(f"[LiteLLM] Exception outer: {e}")
            return self._fallback_analysis(analysis_results, ai_error=str(e))

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

    def _fallback_analysis(self, analysis_results: Dict, ai_error: str | None = None) -> Dict:
        """Return local analysis results when AI analysis fails"""
        logging.info("Using fallback analysis (local results only)")
        result = {
            'original_analysis': analysis_results,
            'ai_insights': [],
            'recommendations': [],
            'ai_status': 'FALLBACK',
            'quality_score': 0,
            'go_no_go_decision': 'REVIEW_REQUIRED',
            'confidence': 0,
            'summary': 'Analysis based on local rules only',
            'critical_issues': []
        }
        if ai_error:
            result['ai_error'] = ai_error
        return result
