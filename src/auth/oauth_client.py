import requests
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class UiPathOAuthClient:
    def __init__(self, base_url: str = None, app_id: str = None, app_secret: str = None, scope: str = None):
        import os
        self.base_url = base_url or os.environ.get("UIPATH_BASE_URL")
        self.app_id = app_id or os.environ.get("UIPATH_APP_ID")
        self.app_secret = app_secret or os.environ.get("UIPATH_APP_SECRET")
        self.scope = scope or os.environ.get("UIPATH_SCOPE", "OR.Default OR.Processes.Read OR.Assets.Read")
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
                print(f"Token request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"Error getting access token: {str(e)}")
            return None