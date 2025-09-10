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
        self.api_version = "2024-10-15"
        
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
            
    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with timeout and error handling"""
        try:
            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = (3.05, 27)  # Connect and read timeouts
                
            # Create a session for connection pooling
            with requests.Session() as session:
                session.headers.update(kwargs.pop('headers', {}))
                
                if method.upper() == 'GET':
                    response = session.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = session.post(url, **kwargs)
                elif method.upper() == 'PATCH':
                    response = session.patch(url, **kwargs)
                elif method.upper() == 'DELETE':
                    response = session.delete(url, **kwargs)
                else:
                    raise SnykAPIError(f"Unsupported HTTP method: {method}")
                
                return response
                
        except requests.exceptions.Timeout as e:
            raise SnykAPIError("Request timed out. Please check your connection and try again.")
        except requests.exceptions.RequestException as e:
            raise SnykAPIError(f"Request failed: {str(e)}")
        except Exception as e:
            raise SnykAPIError(f"Unexpected error: {str(e)}")
    
    def get_organizations(self, group_id: str) -> List[Dict]:
        """Get all organizations in a group using REST API with pagination support"""
        all_orgs = []
        url = f"{self.api_rest_base}/orgs?version={self.api_version}&group_id={group_id}"
        headers = {**self.headers_rest, "snyk-version": self.api_version}
        
        while url:
            response = self._make_request('GET', url, headers=headers)
            data = self._handle_response(response)
            all_orgs.extend(data.get("data", []))
            
            # Handle pagination
            next_url = data.get('links', {}).get('next')
            if next_url:
                if next_url.startswith(('http://', 'https://')):
                    # Full URL provided
                    url = next_url
                elif next_url.startswith('/rest/'):
                    # Remove the leading /rest since api_rest_base already includes it
                    url = f"{self.api_rest_base}{next_url[5:]}"
                elif next_url.startswith('/'):
                    # Relative URL, prepend base URL
                    url = f"{self.api_rest_base}{next_url}"
                else:
                    # Handle any other URL format
                    url = f"{self.api_rest_base}/{next_url}"
            else:
                url = None
                
        return all_orgs
    
    def get_sast_settings(self, org_id: str) -> Dict:
        """Get SAST settings for an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/settings/sast?version={self.api_version}"
        try:
            response = self._make_request('GET', url, headers=self.headers_rest)
            if response.status_code == 404:
                return {"sast_enabled": False}
            data = self._handle_response(response)
            settings = data.get("data", {}).get("attributes", {})
            # Ensure consistent return format
            return {
                "sast_enabled": settings.get("sast_enabled", False),
                "sast_autofix_enabled": settings.get("sast_autofix_enabled", False),
                "sast_autofix_pr_enabled": settings.get("sast_autofix_pr_enabled", False)
            }
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
        response = self._make_request('PATCH', url, headers=self.headers_rest, json=payload)
        self._handle_response(response)
        return True
    
    def get_sast_projects(self, org_id: str) -> List[Dict]:
        """Get all SAST projects for an organization"""
        sast_projects = []
        url = f"{self.api_rest_base}/orgs/{org_id}/projects?version={self.api_version}&limit=100"
        
        while url:
            response = self._make_request('GET', url, headers=self.headers_rest)
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
        response = self._make_request('DELETE', url, headers=self.headers_rest)
        self._handle_response(response)
        return True
