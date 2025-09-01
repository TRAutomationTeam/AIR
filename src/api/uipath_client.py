import requests
# Environment variable mapping (see README for details)
# UIPATH_APP_ID, UIPATH_APP_SECRET, UIPATH_BASE_URL, UIPATH_SCOPE, UIPATH_TENANT, UIPATH_FOLDER, UIPATH_IDENTITY_URL
from typing import Dict, List, Any, Optional
from ..auth.token_manager import TokenManager

class UiPathClient:
    def __init__(self, base_url: str, token_manager: TokenManager):
        self.base_url = base_url
        self.token_manager = token_manager
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make authenticated request to UiPath API"""
        
        headers = kwargs.get('headers', {})
        headers['Authorization'] = f"Bearer {self.token_manager.get_valid_token()}"
        headers['Content-Type'] = 'application/json'
        kwargs['headers'] = headers
        
        url = f"{self.base_url}{endpoint}"
        
        response = requests.request(method, url, **kwargs)
        
        if response.status_code == 401:
            # Token might be expired, try once more with fresh token
            headers['Authorization'] = f"Bearer {self.token_manager._refresh_token()}"
            response = requests.request(method, url, **kwargs)
            
        return response
        
    def get_processes(self, folder_id: Optional[int] = None) -> List[Dict]:
        """Get all processes from Orchestrator"""
        
        endpoint = "/odata/Processes"
        headers = {}
        
        if folder_id:
            headers['X-UIPATH-OrganizationUnitId'] = str(folder_id)
            
        response = self._make_request('GET', endpoint, headers=headers)
        
        if response.status_code == 200:
            return response.json().get('value', [])
        else:
            raise Exception(f"Failed to get processes: {response.status_code} - {response.text}")
            
    def get_process_package(self, process_key: str) -> bytes:
        """Download process package (.nupkg file)"""
        
        endpoint = f"/odata/Processes/UiPath.Server.Configuration.OData.DownloadPackage(key='{process_key}')"
        
        response = self._make_request('GET', endpoint)
        
        if response.status_code == 200:
            return response.content
        else:
            raise Exception(f"Failed to download package: {response.status_code}")
            
    def get_folders(self) -> List[Dict]:
        """Get all folders from Orchestrator"""
        
        endpoint = "/odata/Folders"
        response = self._make_request('GET', endpoint)
        
        if response.status_code == 200:
            return response.json().get('value', [])
        else:
            raise Exception(f"Failed to get folders: {response.status_code}")