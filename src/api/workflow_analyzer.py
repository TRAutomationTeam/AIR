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
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'settings.txt')
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
    # Official UiPath Rule IDs and severities (Error/Warning only)
    # Delay Activity Usage (ST-DBP-026, Error)
    if re.search(r'<ui:Delay', xaml_content):
        violations.append({
            'RuleId': 'ST-DBP-026',
            'RuleName': 'Delay Activity Usage',
            'Severity': 'Error',
            'Description': 'Delay activity detected in workflow.',
            'Recommendation': "Avoid using Delay activity. Use proper synchronization.",
            'File': file_path
        })
    # Hardcoded Delay Activity (ST-PRR-004, Error)
    if re.search(r'Delay="[0-9]+"', xaml_content):
        violations.append({
            'RuleId': 'ST-PRR-004',
            'RuleName': 'Hardcoded Delay Activity',
            'Severity': 'Error',
            'Description': 'Hardcoded delay value detected.',
            'Recommendation': 'Use config/arguments for delay values.',
            'File': file_path
        })
    # Hardcoded Activity Properties (ST-USG-005, Error)
    if re.search(r'Property="[^"]+"', xaml_content):
        violations.append({
            'RuleId': 'ST-USG-005',
            'RuleName': 'Hardcoded Activity Properties',
            'Severity': 'Error',
            'Description': 'Hardcoded activity property detected.',
            'Recommendation': 'Use arguments/config for activity properties.',
            'File': file_path
        })
    # Hardcoded Delays (UI-PRR-004, Error)
    if re.search(r'HardcodedDelay', xaml_content):
        violations.append({
            'RuleId': 'UI-PRR-004',
            'RuleName': 'Hardcoded Delays',
            'Severity': 'Error',
            'Description': 'Hardcoded delay detected.',
            'Recommendation': 'Use config/arguments for delays.',
            'File': file_path
        })
    # Multiple Flowchart Layers (ST-DBP-007, Warning)
    if re.search(r'<ui:Flowchart', xaml_content):
        flowchart_count = len(re.findall(r'<ui:Flowchart', xaml_content))
        if flowchart_count > 1:
            violations.append({
                'RuleId': 'ST-DBP-007',
                'RuleName': 'Multiple Flowchart Layers',
                'Severity': 'Warning',
                'Description': f'{flowchart_count} flowchart layers detected.',
                'Recommendation': 'Reduce flowchart layers for maintainability.',
                'File': file_path
            })
    # Hardcoded Timeout (ST-DBP-021, Warning)
    if re.search(r'Timeout="[0-9]+"', xaml_content):
        violations.append({
            'RuleId': 'ST-DBP-021',
            'RuleName': 'Hardcoded Timeout',
            'Severity': 'Warning',
            'Description': 'Hardcoded timeout detected.',
            'Recommendation': 'Use config/arguments for timeout values.',
            'File': file_path
        })
    # Empty Workflow (ST-DBP-023, Warning)
    if re.search(r'<ui:Sequence[^>]*>\s*</ui:Sequence>', xaml_content):
        violations.append({
            'RuleId': 'ST-DBP-023',
            'RuleName': 'Empty Workflow',
            'Severity': 'Warning',
            'Description': 'Empty workflow detected.',
            'Recommendation': 'Remove or implement logic in empty workflows.',
            'File': file_path
        })
    # Container Usage (UI-DBP-006, Warning)
    if re.search(r'<ui:Container', xaml_content):
        violations.append({
            'RuleId': 'UI-DBP-006',
            'RuleName': 'Container Usage',
            'Severity': 'Warning',
            'Description': 'Container activity detected.',
            'Recommendation': 'Review container usage for best practices.',
            'File': file_path
        })
    # Excel Automation Misuse (UI-DBP-013, Warning)
    if re.search(r'<ui:Excel', xaml_content):
        violations.append({
            'RuleId': 'UI-DBP-013',
            'RuleName': 'Excel Automation Misuse',
            'Severity': 'Warning',
            'Description': 'Excel automation detected. Ensure proper usage.',
            'Recommendation': 'Follow best practices for Excel automation.',
            'File': file_path
        })
    # Simulate Click (UI-PRR-001, Warning)
    if re.search(r'SimulateClick', xaml_content):
        violations.append({
            'RuleId': 'UI-PRR-001',
            'RuleName': 'Simulate Click',
            'Severity': 'Warning',
            'Description': 'Simulate Click detected.',
            'Recommendation': 'Ensure Simulate Click is used appropriately.',
            'File': file_path
        })
    # Simulate Type (UI-PRR-002, Warning)
    if re.search(r'SimulateType', xaml_content):
        violations.append({
            'RuleId': 'UI-PRR-002',
            'RuleName': 'Simulate Type',
            'Severity': 'Warning',
            'Description': 'Simulate Type detected.',
            'Recommendation': 'Ensure Simulate Type is used appropriately.',
            'File': file_path
        })
    # Only include Error and Warning severity in output
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
