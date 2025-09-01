import sys
import logging
import argparse
import os
import git
from pathlib import Path
import json
# Environment variable mapping (see README for details)
# UiPath: UIPATH_APP_ID, UIPATH_APP_SECRET, UIPATH_BASE_URL, UIPATH_SCOPE, UIPATH_TENANT, UIPATH_FOLDER, UIPATH_IDENTITY_URL
# TR Arena: AI_ARENA_API_KEY, AI_ARENA_ENDPOINT, AI_ARENA_MODEL_NAME
# GitHub: GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET

# Import required classes
from ai.code_analyzer import AICodeAnalyzer
from ai.report_generator import ReportGenerator
from api.workflow_analyzer import analyze_project_files

# .... existing imports ....

def analyze_repository(repo_path: str, commit_sha: str = None):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    """Analyzes entire repository for UiPath files"""
    
    logging.info(f"Analyzing repository at {repo_path}")
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
    project_files = find_uipath_files(repo_path)
    
    if not project_files:
        logging.warning("No UiPath project files found")
        return
    
    # Filter to only changed files if available
    if changed_files:
        uipath_changed = [f for f in changed_files if f.endswith(('.xaml', '.json', '.config'))]
        if not uipath_changed:
            logging.info("No UiPath files changed")
            return
        logging.info(f"Analyzing {len(uipath_changed)} changed UiPath files")
    else:
        logging.info(f"Analyzing all {len(project_files)} UiPath files")
    
    # Read secrets from environment variables
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
        analysis_results = analyze_project_files(None, project_files, changed_files)
        logging.info("Running AI enhancement...")
        ai_results = ai_analyzer.analyze_workflow_results(analysis_results)
        logging.info("Generating report...")
        project_info = {
            'name': os.path.basename(repo_path),
            'commit_sha': commit_sha,
            'changed_files': changed_files[:10] if changed_files else None  # Limit for display
        }
        report = report_generator.generate_report(ai_results, project_info)
        with open('report.json', 'w') as f:
            json.dump(report['json_summary'], f, indent=2)
        with open('report.html', 'w') as f:
            f.write(report['html_report'])
        logging.info(f"Analysis complete. Decision: {report['json_summary']['decision']}")
        logging.info(f"Quality Score: {report['json_summary']['quality_score']}/100")
        if report['json_summary']['decision'] == 'NO_GO':
            logging.error("NO_GO decision. Exiting with error code.")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        sys.exit(1)

def find_uipath_files(repo_path: str) -> dict:
    """Find all UiPath-related files in repository"""
    
    # ...existing code...

    # ...existing code...