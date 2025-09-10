import os
import requests
from typing import Dict, Optional, List, Any
from datetime import datetime

class SnykAPIError(Exception):
    """Custom exception for Snyk API errors"""
    pass

class SnykClient:
    def __init__(self, token: str):
        self.token = token
        self.api_v1_base = "https://api.snyk.io/v1"
        self.api_rest_base = "https://api.snyk.io/rest"
        self.api_version = "2024-05-24"
        
        self.headers_v1 = {
            "Authorization": f"token {self.token}",
            "Content-Type": "application/json"
        }
        
        self.headers_rest = {
            "Authorization": f"token {self.token}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json"
        }
    
    def _handle_response(self, response: requests.Response) -> Any:
        """Handle API response and raise appropriate errors"""
        try:
            response.raise_for_status()
            if response.status_code == 204:  # No content
                return None
            return response.json()
        except requests.exceptions.RequestException as e:
            raise SnykAPIError(f"API request failed: {str(e)}")
    
    def get_organizations(self, group_id: str) -> List[Dict]:
        """Get all organizations in a group"""
        url = f"{self.api_v1_base}/group/{group_id}/orgs"
        response = requests.post(url, headers=self.headers_v1)
        data = self._handle_response(response)
        return data.get("orgs", [])
    
    def get_sast_settings(self, org_id: str) -> Dict:
        """Get SAST settings for an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/settings/sast?version={self.api_version}"
        try:
            response = requests.get(url, headers=self.headers_rest)
            if response.status_code == 404:
                return {"sast_enabled": False}
            data = self._handle_response(response)
            return data.get("data", {}).get("attributes", {})
        except SnykAPIError:
            return {"sast_enabled": False}
    
    def disable_sast(self, org_id: str) -> bool:
        """Disable SAST for an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/settings/sast?version={self.api_version}"
        payload = {
            "data": {
                "type": "sast_settings",
                "attributes": { "sast_enabled": False }
            }
        }
        response = requests.patch(url, headers=self.headers_rest, json=payload)
        self._handle_response(response)
        return True
    
    def get_sast_projects(self, org_id: str) -> List[Dict]:
        """Get all SAST projects for an organization"""
        sast_projects = []
        url = f"{self.api_rest_base}/orgs/{org_id}/projects?version={self.api_version}&limit=100"
        
        while url:
            response = requests.get(url, headers=self.headers_rest)
            data = self._handle_response(response)
            
            projects = data.get("data", [])
            for project in projects:
                if project.get("attributes", {}).get("type") == "sast":
                    sast_projects.append({
                        "id": project.get("id"),
                        "name": project.get("attributes", {}).get("name"),
                        "created": project.get("attributes", {}).get("created")
                    })
            
            url = data.get("links", {}).get("next")
        
        return sast_projects
    
    def delete_project(self, org_id: str, project_id: str) -> bool:
        """Delete a project from an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/projects/{project_id}?version={self.api_version}"
        response = requests.delete(url, headers=self.headers_rest)
        self._handle_response(response)
        return True
