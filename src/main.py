import sys
import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
import logging
import argparse
import os
import git
from pathlib import Path
import json
import glob
# Environment variable mapping (see README for details)
# UiPath: UIPATH_APP_ID, UIPATH_APP_SECRET, UIPATH_BASE_URL, UIPATH_SCOPE, UIPATH_TENANT, UIPATH_FOLDER, UIPATH_IDENTITY_URL
# TR Arena: AI_ARENA_API_KEY, AI_ARENA_ENDPOINT, AI_ARENA_MODEL_NAME
# GitHub: GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET

# Import required classes
from ai.code_analyzer import AICodeAnalyzer
from ai.report_generator import ReportGenerator
from api.workflow_analyzer import analyze_workflow_files




# .... existing imports ....


# ...existing code...


def analyze_repository(repo_path: str, commit_sha: str = None):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    """Analyzes entire repository for UiPath files"""
    
    logging.info(f"Analying repository at {repo_path}")
    repo = git.Repo(repo_path)
    
    # Get changed files if commit_sha provided
    changed_files = []
    if commit_sha:
        try:
            commit = repo.commit(commit_sha)
            if commit.parents:  # Not initial commit
                changed_files = [item.a_path for item in commit.diff(commit.parents[0])]
            else:  # Initial commit
                changed_files = [item.a_path for item in commit.diff(None)]
        except Exception as e:
            logging.warning(f"Could not get changed files: {e}")
    
    # Find all UiPath project files
    logging.info("Finding UiPath project files...")
    # Scan only the TR_Sanity_TaxCaddy folder for UiPath files
    uipath_project_path = os.path.join(repo_path, "TR_Sanity_TaxCaddy")
    project_files = find_uipath_files(uipath_project_path)

    if not project_files:
        logging.warning("No UiPath project files found")
        return

    logging.info(f"Found {len(project_files)} UiPath files to analyze.")
    for idx, file_path in enumerate(project_files.keys(), 1):
        logging.info(f"Analyzing file {idx}/{len(project_files)}: {file_path}")
    ai_arena_api_key = os.environ.get("AI_ARENA_API_KEY")
    ai_arena_endpoint = os.environ.get("AI_ARENA_ENDPOINT")
    logging.info("Initializing AI analyzer and report generator...")

    # Hardcode model name
    model_name = "openai_gpt-4-turbo"

    # Initialize analyzers with env vars and hardcoded model name
    ai_analyzer = AICodeAnalyzer(ai_endpoint=ai_arena_endpoint, api_key=ai_arena_api_key, model_name=model_name)
    report_generator = ReportGenerator()

    try:
        logging.info("Running workflow analysis...")
        analysis_results = analyze_workflow_files(project_files, changed_files)
        logging.info("Running AI enhancement...")
        ai_results = ai_analyzer.analyze_workflow_results(analysis_results)
        logging.info("Generating report...")
        project_info = {
            'name': os.path.basename(repo_path),
            'commit_sha': commit_sha,
            'changed_files': changed_files[:10] if changed_files else None  # Limit for display
        }
        report = report_generator.generate_report(ai_results, project_info)
        reports_dir = os.path.join(repo_path, 'AI Reports')
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir, exist_ok=True)
        timestamp = report['report_data']['timestamp'].replace(':', '').replace('-', '').replace('T', '_').split('.')[0]
        base_filename = f"{project_info['name']}_{timestamp}"
        report_json_path = os.path.join(reports_dir, f'{base_filename}.json')
        report_html_path = os.path.join(reports_dir, f'{base_filename}.html')
        with open(report_json_path, 'w', encoding='utf-8') as f:
            json.dump(report['json_summary'], f, indent=2, ensure_ascii=False)
        logging.info(f"Wrote report.json to {report_json_path}")
        with open(report_html_path, 'w', encoding='utf-8') as f:
            f.write(report['html_report'])
        logging.info(f"Wrote report.html to {report_html_path}")
        logging.info(f"Analysis complete. Decision: {report['json_summary']['decision']}")
        logging.info(f"Quality Score: {report['json_summary']['quality_score']}/100")
        # Print rule violations summary table in logs
        violations = report['json_summary'].get('violations', [])
        if violations:
            print("\nRule Violations Summary (Warnings & Errors Only):")
            print("| Rule ID | Rule Name | Severity | Count | Recommendation | Files |")
            print("|---------|-----------|----------|-------|----------------|-------|")
            # Group by RuleId, RuleName, Severity, Recommendation
            grouped = {}
            for v in violations:
                key = (v.get('RuleId'), v.get('RuleName'), v.get('Severity'), v.get('Recommendation'))
                if key not in grouped:
                    grouped[key] = {'count': 0, 'files': set()}
                grouped[key]['count'] += 1
                grouped[key]['files'].add(v.get('FilePath'))
            def color_text(text, color):
                colors = {
                    'red': '\033[91m',
                    'yellow': '\033[93m',
                    'reset': '\033[0m',
                }
                return f"{colors.get(color, '')}{text}{colors['reset']}"

            for (rule_id, rule_name, severity, recommendation), data in grouped.items():
                # Show relative file paths only
                rel_files = [os.path.relpath(f, repo_path) for f in data['files'] if f]
                files_str = ', '.join(sorted(rel_files))
                # Color code severity
                if severity == 'Error':
                    sev_str = color_text(severity, 'red')
                elif severity == 'Warning':
                    sev_str = color_text(severity, 'yellow')
                else:
                    sev_str = severity
                print(f"| {rule_id} | {rule_name} | {sev_str} | {data['count']} | {recommendation} | {files_str} |")
        else:
            print("No warnings or errors found.")
        # Removed any code that uploads or pushes reports to Git
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        sys.exit(1)
        violations = report['json_summary'].get('violations', [])
        if violations:
            print("\nRule Violations Summary (Warnings & Errors Only):")
            print("| Rule ID | Rule Name | Severity | Count | Recommendation | Files |")
            print("|---------|-----------|----------|-------|----------------|-------|")
            # Group by RuleId, RuleName, Severity, Recommendation
            grouped = {}
            for v in violations:
                key = (v.get('RuleId'), v.get('RuleName'), v.get('Severity'), v.get('Recommendation'))
                if key not in grouped:
                    grouped[key] = {'count': 0, 'files': set()}
                grouped[key]['count'] += 1
                grouped[key]['files'].add(v.get('FilePath'))
            for (rule_id, rule_name, severity, recommendation), data in grouped.items():
                files_str = ', '.join(sorted(data['files']))
                print(f"| {rule_id} | {rule_name} | {severity} | {data['count']} | {recommendation} | {files_str} |")
        else:
            print("No warnings or errors found.")
        # Removed any code that uploads or pushes reports to Git
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        sys.exit(1)

def find_uipath_files(repo_path: str) -> dict:
    """Find all UiPath-related files in repository"""
    import os
    uipath_files = {}
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.xaml', '.json', '.config')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        uipath_files[file_path] = f.read()
                except Exception as e:
                    logging.warning(f"Could not read file {file_path}: {e}")

    return uipath_files

def cleanup_old_reports(report_dir):
    html_files = glob.glob(os.path.join(report_dir, '*.html'))
    json_files = glob.glob(os.path.join(report_dir, '*.json'))
    for f in html_files + json_files:
        try:
            os.remove(f)
        except Exception as e:
            print(f"Failed to remove {f}: {e}")

if __name__ == "__main__":
    repo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    report_dir = os.path.join(repo_path, 'AI Reports')
    cleanup_old_reports(report_dir)
    analyze_repository(repo_path)