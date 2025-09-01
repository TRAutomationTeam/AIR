import json
import logging
# Environment variable mapping (see README for details)
# UIPATH_APP_ID, UIPATH_APP_SECRET, UIPATH_BASE_URL, UIPATH_SCOPE, UIPATH_TENANT, UIPATH_FOLDER, UIPATH_IDENTITY_URL
import os
from datetime import datetime, timedelta
from .oauth_client import UiPathOAuthClient

class TokenManager:
    def __init__(self, oauth_client: UiPathOAuthClient, token_file: str = ".token_cache"):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        self.oauth_client = oauth_client
        self.token_file = token_file
        self._token_data = None
        
    def get_valid_token(self) -> str:
        logging.info("Getting valid token...")
        """Get a valid access token, refreshing if necessary"""
        if self._is_token_valid():
            return self._token_data['access_token']
            
        return self._refresh_token()
        
    def _is_token_valid(self) -> bool:
        logging.info("Checking if token is valid...")
        """Check if current token is valid"""
        if not self._token_data:
            self._load_token_from_cache()
            
        if not self._token_data:
            return False
            
        expires_at = datetime.fromisoformat(self._token_data['expires_at'])
        return datetime.now() < expires_at - timedelta(minutes=5)  # 5min buffer
        
    def _refresh_token(self) -> str:
        logging.info("Refreshing token...")
        """Get new access token"""
        access_token = self.oauth_client.get_access_token()
        
        if access_token:
            logging.info("Token refreshed successfully.")
            self._token_data = {
                'access_token': access_token,
                'expires_at': (datetime.now() + timedelta(hours=1)).isoformat()
            }
            self._save_token_to_cache()
            return access_token
            
        raise Exception("Failed to obtain access token")
        
    def _load_token_from_cache(self):
        """Load token from cache file"""
        if os.path.exists(self.token_file):
            try:
                with open(self.token_file, 'r') as f:
                    self._token_data = json.load(f)
            except Exception:
                self._token_data = None
                
    def _save_token_to_cache(self):
        """Save token to cache file"""
        try:
            with open(self.token_file, 'w') as f:
                json.dump(self._token_data, f)
        except Exception as e:
            print(f"Warning: Could not save token cache: {e}")