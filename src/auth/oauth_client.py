import requests
import logging
# Environment variable mapping (see README for details)
# UIPATH_APP_ID, UIPATH_APP_SECRET, UIPATH_BASE_URL, UIPATH_SCOPE, UIPATH_TENANT, UIPATH_FOLDER, UIPATH_IDENTITY_URL
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class UiPathOAuthClient:
    def __init__(self, base_url: str = None, app_id: str = None, app_secret: str = None, scope: str = None, tenant: str = None, folder: str = None, identity_url: str = None):
        import os
        self.base_url = base_url or os.environ.get("UIPATH_BASE_URL")
        self.app_id = app_id or os.environ.get("UIPATH_APP_ID")
        self.app_secret = app_secret or os.environ.get("UIPATH_APP_SECRET")
        self.scope = scope or os.environ.get("UIPATH_SCOPE", "OR.Default OR.Processes.Read OR.Assets.Read")
        self.tenant = tenant or os.environ.get("UIPATH_TENANT")
        self.folder = folder or os.environ.get("UIPATH_FOLDER")
        self.identity_url = identity_url or os.environ.get("UIPATH_IDENTITY_URL")
        self.token_endpoint = f"{self.base_url}/identity/connect/token"
        
    def get_access_token(self) -> Optional[str]:
        """Get OAuth access token using client credentials flow"""
        
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.app_id,
            'client_secret': self.app_secret,
            'scope': self.scope
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            response = requests.post(
                self.token_endpoint,
                data=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('access_token')
            else:
                logging.error(f"Token request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"Error getting access token: {str(e)}")
            return None