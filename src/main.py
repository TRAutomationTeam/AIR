import sys
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
import os
import git
from pathlib import Path
import json
import glob
import yaml
from ai.code_analyzer import AICodeAnalyzer
from ai.report_generator import ReportGenerator
from api.workflow_analyzer import analyze_workflow_files

def normalize_path(path):
    """Normalize Windows paths to handle long paths"""
    if sys.platform == 'win32' and not path.startswith('\\\\?\\'):
        return '\\\\?\\' + os.path.abspath(path)
    return path

# ...existing environment variable mapping and imports...

def analyze_repository(repo_path: str, commit_sha: str = None):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    """Analyzes entire repository for UiPath files"""

    # Load config from settings.txt (now in src/config)
    repo_path = normalize_path(repo_path)
    config_path = normalize_path(os.path.join(repo_path, 'src', 'config', 'settings.txt'))
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # ...existing config loading code...

    logging.info(f"Starting AI analysis for repository: {repo_path}")
    repo = git.Repo(repo_path)

    # ...existing git diff code...

    logging.info("Finding UiPath project files...")
    project_files = find_uipath_files(repo_path)

    # ...existing analysis code...
    # Setup analyzer and report generator
    ai_arena_cfg = config.get('ai_arena', {})
    ai_arena_api_key = ai_arena_cfg.get('api_key')
    ai_arena_endpoint = ai_arena_cfg.get('endpoint')
    model_name = "openai_gpt-4-turbo"

    ai_analyzer = AICodeAnalyzer(
        ai_endpoint=ai_arena_endpoint,
        api_key=ai_arena_api_key,
        model_name=model_name,
        config=config,
        metrics={}
    )
    report_generator = ReportGenerator(config=config, metrics={})

    analysis_results = analyze_workflow_files(project_files, [])
    workflow_count = analysis_results.get('workflow_count', None)
    logging.info(f"Total workflows found: {workflow_count}")
    logging.info("Running AI analysis...")
    ai_results = ai_analyzer.analyze_workflow_results(analysis_results)
    errors = [v for v in ai_results.get('original_analysis', {}).get('rules_violations', []) if v.get('Severity') == 'Error']
    warnings = [v for v in ai_results.get('original_analysis', {}).get('rules_violations', []) if v.get('Severity') == 'Warning']
    logging.info(f"Total errors: {len(errors)}")
    logging.info(f"Total warnings: {len(warnings)}")
    project_info = {
        'name': os.path.basename(repo_path),
        'commit_sha': commit_sha,
        'changed_files': None
    }
    logging.info("Generating report files...")
    report = report_generator.generate_report(ai_results, project_info, repo_path=repo_path)

    reports_dir = normalize_path(os.path.join(repo_path, 'src', 'AI Reports'))
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir, exist_ok=True)

    timestamp = report['report_data']['timestamp'].replace(':', '').replace('-', '').replace('T', '_').split('.')[0]
    base_filename = f"{project_info['name']}_{timestamp}"
    report_json_path = normalize_path(os.path.join(reports_dir, f'{base_filename}.json'))
    report_html_path = normalize_path(os.path.join(reports_dir, f'{base_filename}.html'))

    with open(report_json_path, 'w', encoding='utf-8') as f:
        json.dump(report['json_summary'], f, indent=2, ensure_ascii=False)
    
    with open(report_html_path, 'w', encoding='utf-8') as f:
        f.write(report['html_report'])

def find_uipath_files(repo_path: str) -> dict:
    """Find all UiPath-related files in repository"""
    uipath_files = {}
    repo_path = normalize_path(repo_path)
    
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.xaml', '.json', '.config')):
                file_path = normalize_path(os.path.join(root, file))
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        uipath_files[file_path] = f.read()
                except Exception as e:
                    # Suppressed all logging output
                    pass

    return uipath_files

def cleanup_old_reports(report_dir):
    report_dir = normalize_path(report_dir)
    html_files = glob.glob(normalize_path(os.path.join(report_dir, '*.html')))
    json_files = glob.glob(normalize_path(os.path.join(report_dir, '*.json')))
    
    for f in html_files + json_files:
        try:
            os.remove(normalize_path(f))
        except Exception as e:
            print(f"Failed to remove {f}: {e}")

if __name__ == "__main__":
    repo_path = normalize_path(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    report_dir = normalize_path(os.path.join(repo_path, 'src', 'AI Reports'))
    cleanup_old_reports(report_dir)
    analyze_repository(repo_path)