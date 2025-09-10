import os
import time
import requests
from typing import Dict, Optional, List, Any, Tuple
from datetime import datetime, timedelta
from rich.console import Console

console = Console()

class SnykAPIError(Exception):
    """Custom exception for Snyk API errors"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        self.status_code = status_code
        self.message = message
        super().__init__(self.message)

class RateLimitExceededError(SnykAPIError):
    """Raised when the Snyk API rate limit is exceeded"""
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
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit exceeded
                retry_after = int(response.headers.get('Retry-After', 60))
                raise RateLimitExceededError(
                    f"Rate limit exceeded. Please wait {retry_after} seconds before retrying.",
                    status_code=429
                )
            try:
                error_data = response.json()
                error_msg = error_data.get('message', str(e))
                if 'errors' in error_data and isinstance(error_data['errors'], list):
                    error_msg = "; ".join(
                        f"{err.get('detail', 'Unknown error')} (status: {err.get('status', 'N/A')})"
                        for err in error_data['errors']
                    )
            except ValueError:
                error_msg = str(e)
            
            raise SnykAPIError(f"API request failed: {error_msg}", status_code=response.status_code)
        except requests.exceptions.RequestException as e:
            raise SnykAPIError(f"API request failed: {str(e)}")
            
    def _make_request(self, method: str, url: str, max_retries: int = 3, **kwargs) -> requests.Response:
        """
        Make an HTTP request with timeout, retry, and error handling
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to make the request to
            max_retries: Maximum number of retry attempts for rate limits and transient errors
            **kwargs: Additional arguments to pass to requests.request()
            
        Returns:
            requests.Response: The HTTP response
            
        Raises:
            SnykAPIError: If the request fails after all retries
        """
        # Set default timeout if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (10, 30)  # Increased timeouts for better reliability
            
        # Set default headers if not provided
        if 'headers' not in kwargs:
            kwargs['headers'] = self.headers_rest
            
        retry_delay = 1  # Start with 1 second delay
        
        for attempt in range(max_retries + 1):  # +1 because we want to try max_retries times after the first attempt
            try:
                with requests.Session() as session:
                    session.headers.update(kwargs.pop('headers', {}))
                    response = session.request(method, url, **kwargs)
                    
                    # Check for rate limiting
                    if response.status_code == 429:
                        retry_after = int(response.headers.get('Retry-After', retry_delay))
                        if attempt < max_retries:
                            time.sleep(retry_after)
                            retry_delay *= 2  # Exponential backoff
                            continue
                    
                    return response
                    
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if attempt == max_retries:
                    raise SnykAPIError(f"Connection failed after {max_retries} retries: {str(e)}")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries:
                    raise SnykAPIError(f"Request failed after {max_retries} retries: {str(e)}")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                
        raise SnykAPIError(f"Request failed after {max_retries} retries")
    
    def _process_paginated_response(self, url: str, data_key: str = "data") -> Tuple[List[Dict], Optional[str]]:
        """
        Process a paginated API response and return the data and next URL
        
        Args:
            url: The URL to fetch data from
            data_key: The key in the response containing the data array
            
        Returns:
            Tuple of (data_list, next_url) where next_url is None if there are no more pages
        """
        try:
            response = self._make_request('GET', url)
            data = self._handle_response(response)
            
            # Get the next URL for pagination
            next_url = None
            links = data.get('links', {})
            if 'next' in links and links['next']:
                next_url = links['next']
                # Ensure the URL is absolute
                if next_url.startswith('/'):
                    # Handle both /rest/... and /v1/... style paths
                    if next_url.startswith('/rest/'):
                        next_url = f"https://api.snyk.io{next_url}"
                    else:
                        next_url = f"https://api.snyk.io{next_url}"
                elif not next_url.startswith(('http://', 'https://')):
                    # If it's not a full URL and not starting with /, assume it's a path
                    next_url = f"https://api.snyk.io/rest/{next_url.lstrip('/')}"
            
            return data.get(data_key, []), next_url
            
        except SnykAPIError as e:
            # If we get a 404, it might mean there are no more results
            if e.status_code == 404:
                return [], None
            raise

    def get_organizations(self, group_id: str) -> List[Dict]:
        """
        Get all organizations in a group using REST API with pagination support
        
        Args:
            group_id: The Snyk Group ID to fetch organizations from
            
        Returns:
            List of organization dictionaries
            
        Raises:
            SnykAPIError: If there's an error fetching organizations
        """
        if not group_id or not isinstance(group_id, str) or len(group_id) < 10:  # Basic validation
            raise SnykAPIError(f"Invalid Group ID format: '{group_id}'. Please check and try again.")
            
        all_orgs = []
        url = f"{self.api_rest_base}/orgs?version={self.api_version}&group_id={group_id}&limit=100"
        
        try:
            while url:
                orgs_batch, next_url = self._process_paginated_response(url)
                all_orgs.extend(orgs_batch)
                url = next_url
                
                # Add a small delay between paginated requests to avoid rate limiting
                if url:
                    time.sleep(0.1)
            
            if not all_orgs:
                raise SnykAPIError(
                    f"No organizations found for Group ID: {group_id}. "
                    "Please verify the Group ID and your access permissions."
                )
                
            return all_orgs
            
        except SnykAPIError as e:
            if e.status_code == 404:
                raise SnykAPIError(
                    f"Group ID '{group_id}' is not valid or you don't have access to it. "
                    "Please verify the Group ID and your access permissions."
                ) from e
            if e.status_code == 400:
                raise SnykAPIError(
                    f"Invalid Group ID format: '{group_id}'. "
                    "Please check and try again with a valid Group ID."
                ) from e
            raise SnykAPIError(f"Failed to fetch organizations: {str(e)}") from e
    
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
        Get all SAST projects for an organization with pagination support
        
        Args:
            org_id: The organization ID to get projects from
            
        Returns:
            List of dictionaries containing project information
            
        Raises:
            SnykAPIError: If there's an error fetching projects
        """
        def sanitize_project_data(project: Dict) -> Dict:
            """Sanitize project data to prevent MarkupError and ensure consistent format"""
            attrs = project.get("attributes", {})
            return {
                "id": str(project.get("id", "")),
                "name": str(attrs.get("name", "")).replace('[', '(').replace(']', ')'),
                "created": attrs.get("created"),
                "org_id": org_id,
                "type": attrs.get("type", ""),
                "status": attrs.get("status", "")
            }
            
        if not org_id or not isinstance(org_id, str) or len(org_id) < 10:  # Basic validation
            raise SnykAPIError(f"Invalid Organization ID format: '{org_id}'")
            
        sast_projects = []
        # Construct the initial URL with all required parameters
        url = f"https://api.snyk.io/rest/orgs/{org_id}/projects?version={self.api_version}&limit=100"
        
        try:
            total_processed = 0
            start_time = time.time()
            
            while url:
                try:
                    # Get a batch of projects
                    projects_batch, next_url = self._process_paginated_response(url)
                    
                    # Filter for SAST projects and sanitize data
                    for project in projects_batch:
                        if project.get("attributes", {}).get("type") == "sast":
                            sast_projects.append(sanitize_project_data(project))
                    
                    total_processed += len(projects_batch)
                    
                    # Log progress periodically
                    if len(sast_projects) > 0 and len(sast_projects) % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = total_processed / elapsed if elapsed > 0 else 0
                        console.print(
                            f"Processed {total_processed} projects "
                            f"({len(sast_projects)} SAST) at {rate:.1f} projects/sec",
                            style="dim"
                        )
                    
                    # Handle pagination
                    url = next_url
                    
                    # Add a small delay between paginated requests to avoid rate limiting
                    if url:
                        time.sleep(0.1)
                        
                except RateLimitExceededError as e:
                    # If we hit rate limits, wait and retry
                    retry_after = int(str(e).split()[-2])  # Extract wait time from error message
                    console.print(
                        f"Rate limited. Waiting {retry_after} seconds before retrying...",
                        style="yellow"
                    )
                    time.sleep(retry_after + 1)  # Add 1 second buffer
                    continue
                    
                except SnykAPIError as e:
                    # If we get a 404, it might mean the organization has no projects yet
                    if e.status_code == 404:
                        break
                    raise
            
            # Log completion
            elapsed = time.time() - start_time
            if elapsed > 0:
                rate = total_processed / elapsed
                console.print(
                    f"Completed processing {total_processed} projects "
                    f"({len(sast_projects)} SAST) in {elapsed:.1f} seconds "
                    f"({rate:.1f} projects/sec)",
                    style="green"
                )
                    
            return sast_projects
            
        except Exception as e:
            error_msg = f"Error fetching SAST projects for org {org_id}: {str(e)}"
            error_msg = error_msg.replace('[', '(').replace(']', ')')
            raise SnykAPIError(error_msg) from e
    
    def delete_project(self, org_id: str, project_id: str) -> bool:
        """Delete a project from an organization"""
        url = f"{self.api_rest_base}/orgs/{org_id}/projects/{project_id}?version={self.api_version}"
        response = self._make_request('DELETE', url, headers=self.headers_rest)
        self._handle_response(response)
        return True
