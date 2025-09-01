import requests

# UiPath Cloud API integration template
def get_uipath_access_token(client_id, client_secret, base_url):
    url = f'{base_url}/identity_/connect/token'
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'OR.Platform'
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json()['access_token']

def analyze_xaml_with_uipath_api(access_token, base_url, xaml_file_path):
    # Example endpoint, adjust as needed for your tenant/organization
    url = f'{base_url}/odata/Processes/UiPath.Server.Configuration.OData.AnalyzeWorkflow'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    with open(xaml_file_path, 'r', encoding='utf-8') as f:
        xaml_content = f.read()
    payload = {
        'WorkflowContent': xaml_content
    }
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()
from typing import Dict, List, Any
import json
import logging

def _analyze_xaml_content(xaml_content: str, file_path: str) -> List[Dict]:
    """Analyze XAML content for UiPath best practices and rules."""
    import re
    violations = []
    # 1. Missing annotation/comment
    if '<Annotation>' not in xaml_content:
        violations.append({
            'RuleId': 'XAML001',
            'RuleName': 'Missing Annotation',
            'Severity': 'Warning',
            'FilePath': file_path,
            'Description': 'Workflow is missing <Annotation> for documentation.',
            'Recommendation': 'Add an <Annotation> element to describe workflow purpose.'
        })
    # 2. Excessive workflow complexity (too many activities)
    activity_count = len(re.findall(r'<ui:Sequence|<ui:Flowchart|<ui:StateMachine|<ui:Activity', xaml_content))
    if activity_count > 50:
        violations.append({
            'RuleId': 'XAML002',
            'RuleName': 'Excessive Workflow Complexity',
            'Severity': 'Warning',
            'FilePath': file_path,
            'Description': f'Workflow contains {activity_count} activities, which may be too complex.',
            'Recommendation': 'Consider refactoring into smaller workflows.'
        })
    # 3. Hardcoded values
    if re.search(r'>([0-9]{4,}|true|false|"[^"]+")<', xaml_content):
        violations.append({
            'RuleId': 'XAML003',
            'RuleName': 'Hardcoded Value Detected',
            'Severity': 'Warning',
            'FilePath': file_path,
            'Description': 'Potential hardcoded value found in workflow.',
            'Recommendation': 'Replace hardcoded values with arguments or config settings.'
        })
    # 4. Missing exception handling
    if '<ui:TryCatch' not in xaml_content:
        violations.append({
            'RuleId': 'XAML004',
            'RuleName': 'Missing Exception Handling',
            'Severity': 'Warning',
            'FilePath': file_path,
            'Description': 'No TryCatch block found in workflow.',
            'Recommendation': 'Add TryCatch for robust error handling.'
        })
    # 5. Naming convention violations (simple check)
    bad_names = re.findall(r'Name="([a-zA-Z0-9_]+)"', xaml_content)
    for name in bad_names:
        if not re.match(r'^[A-Z][A-Za-z0-9_]*$', name):
            severity = 'Warning' if name.lower() in ['password', 'username', 'apikey', 'token'] else 'Info'
            violations.append({
                'RuleId': 'XAML005',
                'RuleName': 'Naming Convention Violation',
                'Severity': severity,
                'FilePath': file_path,
                'Description': f'Name "{name}" does not follow PascalCase.',
                'Recommendation': 'Use PascalCase for workflow, variable, and argument names.'
            })
    # 6. Empty sequences
    if re.search(r'<ui:Sequence[^>]*>\s*</ui:Sequence>', xaml_content):
        violations.append({
            'RuleId': 'XAML006',
            'RuleName': 'Empty Sequence',
            'Severity': 'Info',
            'FilePath': file_path,
            'Description': 'Empty <Sequence> found in workflow.',
            'Recommendation': 'Remove or implement logic in empty sequences.'
        })
    # 7. Delay/Timeout detection
    if re.search(r'<ui:Delay|Delay="[0-9]+"|Timeout="[0-9]+"', xaml_content):
        violations.append({
            'RuleId': 'XAML007',
            'RuleName': 'Delay/Timeout Detected',
            'Severity': 'Warning',
            'FilePath': file_path,
            'Description': 'Delay or timeout detected. Ensure values are configurable and not hardcoded.',
            'Recommendation': 'Use config/arguments for delay/timeout values.'
        })
    # 8. Credential/security checks
    if re.search(r'(password|apikey|token|secret|credential)', xaml_content, re.IGNORECASE):
        if re.search(r'("[^"]+")', xaml_content):
            violations.append({
                'RuleId': 'XAML008',
                'RuleName': 'Hardcoded Credential Detected',
                'Severity': 'Error',
                'FilePath': file_path,
                'Description': 'Hardcoded credential or secret detected.',
                'Recommendation': 'Use secure credential activities and config files.'
            })
    if re.search(r'<ui:GetCredential', xaml_content):
        violations.append({
            'RuleId': 'XAML009',
            'RuleName': 'Credential Activity Used',
            'Severity': 'Info',
            'FilePath': file_path,
            'Description': 'Credential activity detected. Ensure secure usage.',
            'Recommendation': 'Store credentials securely and use SecureString.'
        })
    # 9. Retry logic detection
    if re.search(r'RetryScope|RetryNumber|RetryCount', xaml_content):
        violations.append({
            'RuleId': 'XAML010',
            'RuleName': 'Retry Logic Detected',
            'Severity': 'Info',
            'FilePath': file_path,
            'Description': 'Retry logic detected. Ensure proper error handling and retry limits.',
            'Recommendation': 'Configure retry limits and error handling.'
        })
    # 10. Loop optimization (performance)
    if re.search(r'<ui:ForEach|<ui:While|<ui:DoWhile', xaml_content):
        loop_count = len(re.findall(r'<ui:ForEach|<ui:While|<ui:DoWhile', xaml_content))
        if loop_count > 5:
            violations.append({
                'RuleId': 'XAML011',
                'RuleName': 'Excessive Looping',
                'Severity': 'Warning',
                'FilePath': file_path,
                'Description': f'{loop_count} loops detected. Optimize for performance.',
                'Recommendation': 'Reduce loop count or optimize loop logic.'
            })
    # 11. Modular design (maintainability)
    if activity_count > 0 and len(re.findall(r'<ui:InvokeWorkflowFile', xaml_content)) < max(1, activity_count // 20):
        violations.append({
            'RuleId': 'XAML012',
            'RuleName': 'Low Modularity',
            'Severity': 'Warning',
            'FilePath': file_path,
            'Description': 'Few invoked workflows detected. Consider splitting logic into reusable components.',
            'Recommendation': 'Increase modularity by using InvokeWorkflowFile.'
        })
    return violations
from typing import Dict, List, Any
import json
import logging

def analyze_project_files(project_files: Dict[str, str], changed_files: List[str] = None) -> Dict[str, Any]:
    """Analyze project files directly from repository"""
    logging.info("Starting project file analysis...")
    analysis_results = {
        'rules_violations': [],
        'project_info': {
            'total_files': len(project_files),
            'changed_files': len(changed_files) if changed_files else 0
        },
        'files_analyzed': [],
        'summary': {}
    }
    # Focus on changed files if provided
    files_to_analyze = project_files
    if changed_files:
        logging.info(f"Filtering to changed files: {changed_files}")
        files_to_analyze = {
            path: content for path, content in project_files.items()
            if any(path.endswith(changed.split('/')[-1]) for changed in changed_files)
        }
    for file_path, content in files_to_analyze.items():
        logging.info(f"Analyzing file: {file_path}")
        if file_path.endswith('.xaml'):
            violations = _analyze_xaml_content(content, file_path)
            analysis_results['rules_violations'].extend(violations)
            analysis_results['files_analyzed'].append(file_path)
        elif file_path.endswith('.json') and 'project.json' in file_path:
            violations = _analyze_project_json(content, file_path)
            analysis_results['rules_violations'].extend(violations)
            analysis_results['files_analyzed'].append(file_path)
    # Generate summary
    logging.info("Generating analysis summary...")
    analysis_results['summary'] = {
        'total_violations': len(analysis_results['rules_violations']),
        'files_with_issues': len(set(v['FilePath'] for v in analysis_results['rules_violations'])),
        'severity_counts': _count_by_severity(analysis_results['rules_violations'])
    }
    logging.info("Project file analysis complete.")
    return analysis_results

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
        
        # Check for outdated dependencies
        if 'dependencies' in project_data:
            for dep_name, version in project_data['dependencies'].items():
                if _is_outdated_dependency(dep_name, version):
                    violations.append({
                        'RuleId': 'PJ002',
                        'RuleName': 'Outdated Dependency',
                        'Severity': 'Info',
                        'FilePath': file_path,
                        'Description': f'Dependency {dep_name} version {version} may be outdated'
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

def _is_outdated_dependency(dep_name: str, version: str) -> bool:
    """Check if dependency version is outdated (simplified)"""
    # This could be enhanced to check against a database of current versions
    outdated_patterns = ['2019.', '2020.', '2021.']
    return any(version.startswith(pattern) for pattern in outdated_patterns)

def _count_by_severity(violations: List[Dict]) -> Dict[str, int]:
    """Count violations by severity"""
    counts = {}
    for violation in violations:
        severity = violation.get('Severity', 'Unknown')
        counts[severity] = counts.get(severity, 0) + 1
    return counts