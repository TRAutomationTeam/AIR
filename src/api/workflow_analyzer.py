from typing import Dict, List, Any
import json
import logging

def _analyze_xaml_content(xaml_content: str, file_path: str) -> List[Dict]:
    """Analyze XAML content for UiPath best practices and rules."""
    import re
    violations = []
    # Load official rules from settings.txt
    import yaml
    import os
    from pathlib import Path
    
    # First try to get config from the project root
    repo_root = Path(file_path).resolve()
    while repo_root.parent != repo_root:
        if (repo_root / '.git').exists():
            break
        repo_root = repo_root.parent

    config_path = repo_root / 'src' / 'config' / 'settings.txt'
    if not config_path.exists():
        # Fallback to relative path from module
        config_path = Path(os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.txt'))
    
    logging.info(f"Loading rules from: {config_path}")
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    official_rules = config.get('official_rules', [])

    for rule in official_rules:
        pattern = rule.get('pattern')
        threshold = rule.get('threshold')
        if pattern:
            import re
            matches = re.findall(pattern, xaml_content)
            if threshold is not None:
                if len(matches) > threshold:
                    violations.append({
                        'RuleId': rule['id'],
                        'RuleName': rule['name'],
                        'Severity': rule['severity'],
                        'Description': f"{len(matches)} matches for pattern '{pattern}' (threshold: {threshold})",
                        'Recommendation': rule.get('recommendation', ''),
                        'File': file_path
                    })
            elif matches:
                violations.append({
                    'RuleId': rule['id'],
                    'RuleName': rule['name'],
                    'Severity': rule['severity'],
                    'Description': f"Pattern '{pattern}' found in workflow.",
                    'Recommendation': rule.get('recommendation', ''),
                    'File': file_path
                })
    # All rules are loaded from settings.txt, no hardcoded rules here
    # Only include Error and Warning severity in output
    # Process workflow and activity count metrics
    metrics = {
        'workflow_count': sum(1 for _ in re.finditer(r'<Activity[^>]*>', xaml_content)),
        'activities_count': len(re.findall(r'<ui:[A-Za-z0-9_]+', xaml_content))
    }
    
    # Check metric-based rules
    for rule in official_rules:
        if rule.get('type') == 'custom':
            metric_name = rule.get('metric')
            threshold = rule.get('threshold')
            if metric_name and threshold is not None and metric_name in metrics:
                metric_value = metrics[metric_name]
                if metric_value > threshold:
                    violations.append({
                        'RuleId': rule['id'],
                        'RuleName': rule['name'],
                        'Severity': rule['severity'],
                        'Description': f"{rule['name']} check failed. Found {metric_value}, threshold is {threshold}",
                        'Recommendation': rule.get('recommendation', ''),
                        'File': file_path,
                        'Count': metric_value
                    })

    violations[:] = [v for v in violations if v['Severity'] in ('Error', 'Warning')]
    return violations

def _analyze_project_json(json_content: str, file_path: str) -> List[Dict]:
    """Analyze project.json file"""
    
    violations = []
    
    try:
        project_data = json.loads(json_content)
        
        # Check for missing required fields
        required_fields = ['name', 'description', 'main', 'dependencies']
        for field in required_fields:
            if field not in project_data or not project_data[field]:
                violations.append({
                    'RuleId': 'PJ001',
                    'RuleName': f'Missing {field}',
                    'Severity': 'Warning',
                    'FilePath': file_path,
                    'Description': f'Project.json missing required field: {field}'
                })
        
                    
    except json.JSONDecodeError:
        violations.append({
            'RuleId': 'PJ000',
            'RuleName': 'Invalid JSON',
            'Severity': 'Error',
            'FilePath': file_path,
            'Description': 'project.json contains invalid JSON'
        })
    
    return violations
def analyze_workflow_files(project_files: Dict[str, str], changed_files: List[str] = None) -> Dict[str, Any]:
    analysis_results = {
        'rules_violations': [],
        'files_analyzed': [],
        'activities_count': {}  # file_path -> count
    }
    files_to_analyze = {
        path: content for path, content in project_files.items()
        if not changed_files or any(path.endswith(changed.split('/')[-1]) for changed in changed_files)
    }
    # Count all .xaml files for workflow_count metric
    workflow_count = sum(1 for file_path in files_to_analyze if file_path.endswith('.xaml'))
    analysis_results['workflow_count'] = workflow_count
    for file_path, content in files_to_analyze.items():
        if file_path.endswith('.xaml'):
            # Count activities: look for <ui:Activity or <ui:Sequence or <ui:Assign etc.
            import re
            # This regex matches most UiPath activities (customize as needed)
            activity_tags = re.findall(r'<ui:[A-Za-z0-9_]+', content)
            activity_count = len(activity_tags)
            analysis_results['activities_count'][file_path] = activity_count
            violations = _analyze_xaml_content(content, file_path)
            analysis_results['rules_violations'].extend(violations)
            analysis_results['files_analyzed'].append(file_path)
        elif file_path.endswith('project.json'):
            violations = _analyze_project_json(content, file_path)
            analysis_results['rules_violations'].extend(violations)
            analysis_results['files_analyzed'].append(file_path)
    return analysis_results
