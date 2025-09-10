import os
import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from snyk_sast_tool.core.api_client import SnykClient, SnykAPIError
from snyk_sast_tool.utils.report_generator import ReportGenerator

app = typer.Typer(help="Snyk SAST Management Tool")
console = Console()

class SnykSASTTool:
    def __init__(self, token: str):
        self.client = SnykClient(token)
        self.report_generator = ReportGenerator()
    
    def audit_organizations(self, group_id: str) -> dict:
        """Audit SAST settings across organizations in a group"""
        with Progress() as progress:
            task = progress.add_task("[cyan]Auditing organizations...", total=100)
            
            orgs = self.client.get_organizations(group_id)
            if not orgs:
                console.print("[red]❌ No organizations found or error occurred.[/red]")
                return {}
            
            progress.update(task, advance=20, total=len(orgs) + 20)
            
            audit_results = {
                "group_id": group_id,
                "sast_enabled_orgs": [],
                "sast_disabled_orgs": []
            }
            
            for i, org in enumerate(orgs, 1):
                org_name = org.get('attributes', {}).get('name', f"Organization {i}")
                org_id = org.get('id')
                progress.update(task, description=f"[cyan]Checking {org_name}...")
                
                settings = self.client.get_sast_settings(org_id)
                org_data = {
                    "id": org_id,
                    "name": org_name,
                    "settings": settings
                }
                
                if settings and settings.get("sast_enabled"):
                    org_data["sast_projects"] = self.client.get_sast_projects(org_id)
                    audit_results["sast_enabled_orgs"].append(org_data)
                    console.print(f"[green]✓[/green] {org_name} (ID: {org_id}): SAST Enabled")
                else:
                    audit_results["sast_disabled_orgs"].append(org_data)
                    console.print(f"[yellow]•[/yellow] {org_name} (ID: {org_id}): SAST Disabled")
                
                progress.update(task, advance=1, completed=20+i)
            
            return audit_results
    
    def disable_sast(self, org_id: str, org_name: str = "") -> bool:
        """Disable SAST for a specific organization"""
        if not org_name:
            # Try to get the organization name
            orgs = self.client.get_organizations()
            for org in orgs:
                if org.get('id') == org_id:
                    org_name = org.get('attributes', {}).get('name', f"organization {org_id}")
                    break
            else:
                org_name = f"organization {org_id}"
            
        console.print(f"\n[bold]Disabling SAST for {org_name} (ID: {org_id})[/bold]")
        
        try:
            success = self.client.disable_sast(org_id)
            if success:
                console.print(f"[green]✓ Successfully disabled SAST for {org_name}[/green]")
            else:
                console.print(f"[yellow]! SAST was already disabled for {org_name}[/yellow]")
            return success
        except SnykAPIError as e:
            console.print(f"[red]❌ Error disabling SAST: {str(e)}[/red]")
            return False
    
    def delete_sast_projects(self, org_id: str, project_ids: List[str]) -> dict:
        """Delete SAST projects from an organization"""
        results = {"success": [], "failed": []}
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Deleting projects...", total=len(project_ids))
            
            for project_id in project_ids:
                try:
                    success = self.client.delete_project(org_id, project_id)
                    if success:
                        results["success"].append(project_id)
                        console.print(f"[green]✓ Deleted project {project_id}[/green]")
                    else:
                        results["failed"].append(project_id)
                        console.print(f"[yellow]⚠️  Failed to delete project {project_id}[/yellow]")
                except Exception as e:
                    results["failed"].append(project_id)
                    console.print(f"[red]❌ Error deleting project {project_id}: {str(e)}[/red]")
                
                progress.update(task, advance=1)
        
        return results
        
    def delete_all_sast_projects(self, org_id: str, org_name: str = "") -> dict:
        """Delete all SAST projects from an organization"""
        if not org_name:
            # Try to get the organization name
            orgs = self.client.get_organizations()
            for org in orgs:
                if org.get('id') == org_id:
                    org_name = org.get('attributes', {}).get('name', f"organization {org_id}")
                    break
            else:
                org_name = f"organization {org_id}"
        
        console.print(f"\n[bold]Fetching SAST projects for {org_name} (ID: {org_id})[/bold]")
        
        try:
            # Get all SAST projects for the organization
            sast_projects = self.client.get_sast_projects(org_id)
            if not sast_projects:
                console.print("[yellow]⚠️  No SAST projects found to delete.[/yellow]")
                return {"success": [], "failed": []}
                
            console.print(f"Found {len(sast_projects)} SAST projects to delete.")
            
            # Get project IDs
            project_ids = [p.get('id') for p in sast_projects if p.get('id')]
            
            if not project_ids:
                console.print("[yellow]⚠️  No valid project IDs found.[/yellow]")
                return {"success": [], "failed": []}
                
            # Confirm before deletion
            if not typer.confirm(f"Are you sure you want to delete {len(project_ids)} SAST projects from {org_name}?"):
                console.print("[yellow]Operation cancelled by user.[/yellow]")
                return {"success": [], "failed": []}
                
            # Delete the projects
            return self.delete_sast_projects(org_id, project_ids)
            
        except SnykAPIError as e:
            console.print(f"[red]❌ Error fetching SAST projects: {str(e)}[/red]")
            return {"success": [], "failed": []}

@app.command()
def audit(
    group_id: str = typer.Option(..., "--group-id", "-g", help="Snyk Group ID to audit"),
    output: str = typer.Option("report", "--output", "-o", help="Output filename prefix"),
    format: str = typer.Option("both", "--format", "-f", help="Output format: json, excel, or both")
):
    """Audit SAST settings across organizations in a group"""
    token = os.getenv("SNYK_TOKEN")
    if not token:
        console.print("[red]❌ SNYK_TOKEN environment variable not set[/red]")
        raise typer.Exit(1)
    
    tool = SnykSASTTool(token)
    
    console.print(f"[bold]🔍 Auditing SAST settings for Group ID: {group_id}[/bold]")
    
    audit_results = tool.audit_organizations(group_id)
    
    if not audit_results:
        console.print("[yellow]No results to export.[/yellow]")
        return
    
    # Generate reports
    if format in ["json", "both"]:
        json_report = tool.report_generator.prepare_audit_report(audit_results)
        json_filename = f"{output}.json"
        tool.report_generator.save_json(json_report, json_filename)
        console.print(f"[green]✓ JSON report saved to {json_filename}[/green]")
    
    if format in ["excel", "both"]:
        flat_report = tool.report_generator.prepare_flat_report(audit_results)
        excel_filename = f"{output}.xlsx"
        tool.report_generator.save_excel(flat_report, excel_filename)
        console.print(f"[green]✓ Excel report saved to {excel_filename}[/green]")

@app.command()
def disable(
    org_id: str = typer.Argument(..., help="Organization ID to disable SAST for"),
    org_name: str = typer.Option("", "--name", "-n", help="Organization name (for display purposes)")
):
    """Disable SAST for a specific organization"""
    token = os.getenv("SNYK_TOKEN")
    if not token:
        console.print("[red]❌ SNYK_TOKEN environment variable not set[/red]")
        raise typer.Exit(1)
    
    tool = SnykSASTTool(token)
    tool.disable_sast(org_id, org_name)

@app.command()
def delete_projects(
    org_id: str = typer.Argument(..., help="Organization ID containing the projects"),
    project_ids: List[str] = typer.Argument(None, help="List of project IDs to delete. If not provided, all SAST projects will be deleted.")
):
    """Delete SAST projects from an organization"""
    token = os.getenv("SNYK_TOKEN")
    if not token:
        console.print("[red]❌ SNYK_TOKEN environment variable not set[/red]")
        raise typer.Exit(1)
    
    tool = SnykSASTTool(token)
    
    if not project_ids:
        # If no project IDs provided, delete all SAST projects
        org_name = f"organization {org_id}"  # Default name if we can't find the org
        
        # Get the group ID from the organization
        try:
            # First get the organization details to find its group ID
            org_url = f"https://api.snyk.io/rest/orgs/{org_id}?version=2024-10-15"
            response = tool.client._make_request('GET', org_url, headers=tool.client.headers_rest)
            if response.status_code == 200:
                org_data = response.json()
                group_id = org_data.get('data', {}).get('attributes', {}).get('group_id')
                if group_id:
                    # Now get all organizations in this group to find the name
                    orgs = tool.client.get_organizations(group_id)
                    for org in orgs:
                        if org.get('id') == org_id:
                            org_name = org.get('attributes', {}).get('name', f"organization {org_id}")
                            break
        except Exception as e:
            console.print(f"[yellow]⚠️  Could not fetch organization details: {str(e)}[/yellow]")
        
        console.print(f"[yellow]⚠️  No project IDs provided. Will delete all SAST projects in {org_name} (ID: {org_id}).[/yellow]")
        results = tool.delete_all_sast_projects(org_id, org_name)
    else:
        # Delete specific projects
        results = tool.delete_sast_projects(org_id, project_ids)
    
    console.print("\n[bold]Deletion Summary:[/bold]")
    console.print(f"[green]✓ Successfully deleted: {len(results['success'])} projects[/green]")
    if results["failed"]:
        console.print(f"[red]❌ Failed to delete: {len(results['failed'])} projects[/red]")
        console.print("Failed project IDs:", ", ".join(results["failed"]))

def main():
    app()

if __name__ == "__main__":
    main()
