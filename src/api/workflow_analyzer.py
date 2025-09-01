import json
import logging
from typing import Dict, List, Any

def analyze_project_files(self, project_files: Dict[str, str], 
                         changed_files: List[str] = None) -> Dict[str, Any]:
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
            violations = self._analyze_xaml_content(content, file_path)
            analysis_results['rules_violations'].extend(violations)
            analysis_results['files_analyzed'].append(file_path)
        elif file_path.endswith('.json') and 'project.json' in file_path:
            violations = self._analyze_project_json(content, file_path)
            analysis_results['rules_violations'].extend(violations)
            analysis_results['files_analyzed'].append(file_path)
    
    # Generate summary
    logging.info("Generating analysis summary...")
    analysis_results['summary'] = {
        'total_violations': len(analysis_results['rules_violations']),
        'files_with_issues': len(set(v['FilePath'] for v in analysis_results['rules_violations'])),
        'severity_counts': self._count_by_severity(analysis_results['rules_violations'])
    }
    
    logging.info("Project file analysis complete.")
    return analysis_results

def _analyze_project_json(self, json_content: str, file_path: str) -> List[Dict]:
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
                if self._is_outdated_dependency(dep_name, version):
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

def _is_outdated_dependency(self, dep_name: str, version: str) -> bool:
    """Check if dependency version is outdated (simplified)"""
    # This could be enhanced to check against a database of current versions
    outdated_patterns = ['2019.', '2020.', '2021.']
    return any(version.startswith(pattern) for pattern in outdated_patterns)

def _count_by_severity(self, violations: List[Dict]) -> Dict[str, int]:
    """Count violations by severity"""
    counts = {}
    for violation in violations:
        severity = violation.get('Severity', 'Unknown')
        counts[severity] = counts.get(severity, 0) + 1
    return counts