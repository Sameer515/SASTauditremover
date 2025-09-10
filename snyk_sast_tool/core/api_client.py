import os
import requests
from typing import Dict, Optional, List, Any
from datetime import datetime
from rich.console import Console

console = Console()

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
        
        try:
            while url:
                try:
                    response = self._make_request('GET', url, headers=headers)
                    data = self._handle_response(response)
                    all_orgs.extend(data.get("data", []))
                    
                    # Handle pagination
                    next_url = data.get('links', {}).get('next')
                    if next_url:
                        if next_url.startswith(('http://', 'https://')):
                            url = next_url
                        elif next_url.startswith('/rest/'):
                            url = f"{self.api_rest_base}{next_url[5:]}"
                        elif next_url.startswith('/'):
                            url = f"{self.api_rest_base}{next_url}"
                        else:
                            url = f"{self.api_rest_base}/{next_url}"
                    else:
                        url = None
                except SnykAPIError as e:
                    if "404" in str(e):
                        raise SnykAPIError(f"Group ID '{group_id}' is not valid or you don't have access to it.")
                    if "400" in str(e):
                        raise SnykAPIError(f"Invalid Group ID format: '{group_id}'. Please check and try again.")
                    raise
                    
            if not all_orgs:
                raise SnykAPIError(f"No organizations found for Group ID: {group_id}")
                
            return all_orgs
            
        except requests.exceptions.RequestException as e:
            if "404" in str(e):
                raise SnykAPIError(f"Group ID '{group_id}' is not valid or you don't have access to it.")
            if "400" in str(e):
                raise SnykAPIError(f"Invalid Group ID format: '{group_id}'. Please check and try again.")
            raise SnykAPIError(f"Failed to fetch organizations: {str(e)}")
    
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
    
    def enable_sast(self, org_id: str, org_name: str = "") -> bool:
        """Enable SAST for an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/settings/sast?version={self.api_version}"
        
        # First, get the current settings to ensure we have the latest data
        try:
            current_settings = self.get_sast_settings(org_id)
            if current_settings.get('sast_enabled', False):
                console.print(f"[yellow]ℹ️  SAST is already enabled for {org_name or org_id}[/yellow]")
                return True  # Already enabled
        except SnykAPIError as e:
            console.print(f"[yellow]⚠️  Could not fetch current SAST settings: {str(e)}[/yellow]")
        
        # Prepare the payload with exact structure required by the API
        payload = {
            "data": {
                "type": "sast_settings",
                "id": org_id,
                "attributes": {
                    "sast_enabled": True
                }
            }
        }
        
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": f"token {self.token}",
            "snyk-version": self.api_version,
            "Accept": "application/vnd.api+json"
        }
        
        try:
            # Add debug logging
            console.print(f"[debug] Sending PATCH request to: {url}")
            console.print(f"[debug] Headers: {headers}")
            console.print(f"[debug] Payload: {payload}")
            
            response = self._make_request('PATCH', url, headers=headers, json=payload)
            
            # Debug response
            console.print(f"[debug] Response status: {response.status_code}")
            try:
                console.print(f"[debug] Response body: {response.text}")
                response_data = response.json()
            except:
                console.print("[debug] No response body")
                response_data = {}
            
            # Check for success status codes (200, 201, 204)
            if response.status_code in [200, 201, 204]:
                # Verify SAST is enabled in the response if available
                if response_data.get('data', {}).get('attributes', {}).get('sast_enabled', False):
                    console.print(f"[green]✓ Successfully enabled SAST for {org_name or org_id}[/green]")
                    return True
                else:
                    console.print(f"[yellow]⚠️  SAST status unknown for {org_name or org_id}. Please verify in the Snyk UI.[/yellow]")
                    return True
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('errors', [{'detail': str(error_data)}])
                    if isinstance(error_msg, list):
                        error_msg = error_msg[0].get('detail', 'Unknown error')
                except Exception as e:
                    error_msg = f"Failed to parse error response: {str(e)}"
                
                console.print(f"[red]❌ Failed to enable SAST for {org_name or org_id} (HTTP {response.status_code}): {error_msg}[/red]")
                return False
                
        except SnykAPIError as e:
            # Check if the error indicates SAST is already enabled
            error_msg = str(e).lower()
            if any(msg in error_msg for msg in ["already enabled", "is enabled"]):
                return True
            console.print(f"[red]❌ Error enabling SAST for {org_name or org_id}: {error_msg}[/red]")
            return False
    
    def disable_sast(self, org_id: str, org_name: str = "") -> bool:
        """Disable SAST for an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/settings/sast?version={self.api_version}"
        
        # First, get the current settings to ensure we have the latest data
        try:
            current_settings = self.get_sast_settings(org_id)
            if not current_settings.get('sast_enabled', True):
                console.print(f"[yellow]ℹ️  SAST is already disabled for {org_name or org_id}[/yellow]")
                return True  # Already disabled
        except SnykAPIError as e:
            console.print(f"[yellow]⚠️  Could not fetch current SAST settings: {str(e)}[/yellow]")
        
        # Prepare the payload with exact structure required by the API
        payload = {
            "data": {
                "type": "sast_settings",
                "id": org_id,
                "attributes": {
                    "sast_enabled": False
                }
            }
        }
        
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": f"token {self.token}",
            "snyk-version": self.api_version,
            "Accept": "application/vnd.api+json"
        }
        
        try:
            # Add debug logging
            console.print(f"[debug] Sending PATCH request to: {url}")
            console.print(f"[debug] Headers: {headers}")
            console.print(f"[debug] Payload: {payload}")
            
            response = self._make_request('PATCH', url, headers=headers, json=payload)
            
            # Debug response
            console.print(f"[debug] Response status: {response.status_code}")
            try:
                console.print(f"[debug] Response body: {response.text}")
                response_data = response.json()
            except:
                console.print("[debug] No response body")
                response_data = {}
            
            # Check for success status codes (200, 201, 204)
            if response.status_code in [200, 201, 204]:
                # Verify SAST is disabled in the response if available
                if not response_data.get('data', {}).get('attributes', {}).get('sast_enabled', True):
                    console.print(f"[green]✓ Successfully disabled SAST for {org_name or org_id}[/green]")
                    return True
                else:
                    console.print(f"[yellow]⚠️  SAST status unknown for {org_name or org_id}. Please verify in the Snyk UI.[/yellow]")
                    return True
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('errors', [{'detail': str(error_data)}])
                    if isinstance(error_msg, list):
                        error_msg = error_msg[0].get('detail', 'Unknown error')
                except Exception as e:
                    error_msg = f"Failed to parse error response: {str(e)}"
                
                console.print(f"[red]❌ Failed to disable SAST for {org_name or org_id} (HTTP {response.status_code}): {error_msg}[/red]")
                return False
                
        except SnykAPIError as e:
            # Check if the error indicates SAST is already disabled
            error_msg = str(e).lower()
            if any(msg in error_msg for msg in ["already disabled", "is disabled"]):
                return True
            console.print(f"[red]❌ Error disabling SAST for {org_name or org_id}: {error_msg}[/red]")
            return False
    
    def get_sast_projects(self, org_id: str) -> List[Dict]:
        """
        Get all SAST projects for an organization
        
        Args:
            org_id: The organization ID to get projects from
            
        Returns:
            List of dictionaries containing project information
            
        Raises:
            SnykAPIError: If there's an error fetching projects
        """
        def sanitize_project_data(project: Dict) -> Dict:
            """Sanitize project data to prevent MarkupError"""
            attrs = project.get("attributes", {})
            return {
                "id": str(project.get("id", "")),
                "name": str(attrs.get("name", "")).replace('[', '(').replace(']', ')'),
                "created": attrs.get("created")
            }
            
        sast_projects = []
        url = f"{self.api_rest_base}/orgs/{org_id}/projects?version={self.api_version}&limit=100"
        
        try:
            while url:
                try:
                    response = self._make_request('GET', url, headers=self.headers_rest)
                    data = self._handle_response(response)
                    
                    projects = data.get("data", [])
                    for project in projects:
                        if project.get("attributes", {}).get("type") == "sast":
                            sast_projects.append(sanitize_project_data(project))
                    
                    next_url = data.get("links", {}).get("next")
                    # Only update URL if it's a relative URL (starts with /)
                    if next_url and next_url.startswith('/'):
                        url = f"{self.api_rest_base}{next_url}"
                    else:
                        url = next_url
                    
                except SnykAPIError as e:
                    # If we get a 404, it might mean the organization has no projects yet
                    if "404" in str(e):
                        break
                    raise
                    
        except Exception as e:
            error_msg = f"Error fetching SAST projects for org {org_id}: {str(e)}"
            error_msg = error_msg.replace('[', '(').replace(']', ')')
            raise SnykAPIError(error_msg) from e
        
        return sast_projects
    
    def delete_project(self, org_id: str, project_id: str) -> bool:
        """Delete a project from an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/projects/{project_id}?version={self.api_version}"
        response = self._make_request('DELETE', url, headers=self.headers_rest)
        self._handle_response(response)
        return True
