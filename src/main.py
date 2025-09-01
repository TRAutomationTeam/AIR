import sys
import argparse
import os
import git
from pathlib import Path
import json

# Import required classes
from ai.code_analyzer import AICodeAnalyzer
from ai.report_generator import ReportGenerator
from api.workflow_analyzer import analyze_project_files

# .... existing imports ....

def analyze_repository(repo_path: str, commit_sha: str = None):
    """Analyzes entire repository for UiPath files"""
    
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
            print(f"Warning: Could not get changed files: {e}")
    
    # Find all UiPath project files
    project_files = find_uipath_files(repo_path)
    
    if not project_files:
        print("No UiPath project files found")
        return
    
    # Filter to only changed files if available
    if changed_files:
        uipath_changed = [f for f in changed_files if f.endswith(('.xaml', '.json', '.config'))]
        if not uipath_changed:
            print("No UiPath files changed")
            return
        print(f"Analyzing {len(uipath_changed)} changed UiPath files")
    else:
        print(f"Analyzing all {len(project_files)} UiPath files")
    
    # Run analysis
    try:
    # Read secrets from environment variables
    uipath_app_id = os.environ.get("UIPATH_APP_ID")
    uipath_app_secret = os.environ.get("UIPATH_APP_SECRET")
    uipath_base_url = os.environ.get("UIPATH_BASE_URL")
    ai_arena_api_key = os.environ.get("AI_ARENA_API_KEY")
    ai_arena_endpoint = os.environ.get("AI_ARENA_ENDPOINT")

    # Initialize analyzers with env vars
    ai_analyzer = AICodeAnalyzer(ai_endpoint=ai_arena_endpoint, api_key=ai_arena_api_key)
    report_generator = ReportGenerator()

    # Run workflow analysis
    analysis_results = analyze_project_files(None, project_files, changed_files)
    ai_results = ai_analyzer.analyze_workflow_results(analysis_results)

        # Generate report
        project_info = {
            'name': os.path.basename(repo_path),
            'commit_sha': commit_sha,
            'changed_files': changed_files[:10] if changed_files else None  # Limit for display
        }

        report = report_generator.generate_report(ai_results, project_info)

        # Save report files
        with open('report.json', 'w') as f:
            json.dump(report['json_summary'], f, indent=2)

        with open('report.html', 'w') as f:
            f.write(report['html_report'])

        print(f"Analysis complete. Decision: {report['json_summary']['decision']}")
        print(f"Quality Score: {report['json_summary']['quality_score']}/100")

        # Exit with error code if NO_GO
        if report['json_summary']['decision'] == 'NO_GO':
            sys.exit(1)

    except Exception as e:
        print(f"Analysis failed: {e}")
        sys.exit(1)

def find_uipath_files(repo_path: str) -> dict:
    """Find all UiPath-related files in repository"""
    
    project_files = {}
    repo_path = Path(repo_path)
    
    # Look for project.json files (UiPath project indicators)
    for project_json in repo_path.rglob('project.json'):
        project_dir = project_json.parent
        
        # Get all XAML files in this project
        xaml_files = list(project_dir.rglob('*.xaml'))
        
        for xaml_file in xaml_files:
            rel_path = str(xaml_file.relative_to(repo_path))
            with open(xaml_file, 'r', encoding='utf-8') as f:
                project_files[rel_path] = f.read()
    
    return project_files

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='UiPath AI Code Review')
    parser.add_argument('command', choices=['analyze_repository', 'run_server'])
    parser.add_argument('--repo-path', help='Repository path')
    parser.add_argument('--commit-sha', help='Commit SHA to analyze')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    
    args = parser.parse_args()
    
    if args.command == 'analyze_repository':
        if not args.repo_path:
            print("--repo-path required for analyze_repository")
            sys.exit(1)
        analyze_repository(args.repo_path, args.commit_sha)
    
    elif args.command == 'run_server':
        # Flask app import and run
        from flask import Flask
        app = Flask(__name__)
        app.run(host='0.0.0.0', port=args.port, debug=False)