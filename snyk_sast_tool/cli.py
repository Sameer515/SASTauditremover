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
        if not org_id or not org_id.strip():
            console.print("[red]❌ Organization ID cannot be empty[/red]")
            return False
            
        org_id = org_id.strip()
        
        try:
            if not org_name:
                # Try to get the organization name
                try:
                    org_url = f"https://api.snyk.io/rest/orgs/{org_id}?version=2024-10-15"
                    response = self.client._make_request('GET', org_url, headers=self.client.headers_rest)
                    if response.status_code == 200:
                        org_data = response.json()
                        org_name = org_data.get('data', {}).get('attributes', {}).get('name', f"organization {org_id}")
                    else:
                        org_name = f"organization {org_id}"
                except Exception as e:
                    console.print(f"[yellow]⚠️  Could not fetch organization name: {str(e)}[/yellow]")
                    org_name = f"organization {org_id}"
            
            console.print(f"\n[bold]Disabling SAST for {org_name} (ID: {org_id})[/bold]")
            
            success = self.client.disable_sast(org_id)
            if success:
                console.print(f"[green]✓ Successfully disabled SAST for {org_name}[/green]")
            else:
                console.print(f"[yellow]! SAST was already disabled for {org_name}[/yellow]")
            return success
            
        except SnykAPIError as e:
            console.print(f"[red]❌ Error disabling SAST for {org_id}: {str(e)}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]❌ Unexpected error processing {org_id}: {str(e)}[/red]")
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

def _validate_org_id(org_id: str) -> str:
    """Validate organization ID is not empty"""
    if not org_id or not org_id.strip():
        console.print("[red]❌ Organization ID cannot be empty[/red]")
        raise typer.Exit(1)
    return org_id.strip()

def _get_orgs_from_file(file_path: str) -> List[dict]:
    """Read organization IDs and names from a file"""
    if not os.path.exists(file_path):
        console.print(f"[red]❌ File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    orgs = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    parts = line.split(',')
                    if len(parts) >= 1:
                        org_id = parts[0].strip()
                        org_name = parts[1].strip() if len(parts) > 1 else ""
                        if org_id:  # Only add if org_id is not empty
                            orgs.append({"id": org_id, "name": org_name})
        
        if not orgs:
            console.print("[yellow]⚠️  No valid organization entries found in the file[/yellow]")
            raise typer.Exit(1)
            
        return orgs
    except Exception as e:
        console.print(f"[red]❌ Error reading file: {str(e)}[/red]")
        raise typer.Exit(1)

@app.command()
def disable(
    org_id: str = typer.Argument(
        None,
        help="Organization ID to disable SAST for. Not required if using --file"
    ),
    file_path: str = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to a file containing organizations to disable (one per line, format: org_id,org_name)",
        callback=lambda x: x.strip() if x else None
    ),
    skip_confirm: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt"
    )
):
    """
    Disable SAST for one or more organizations.
    
    You can specify organizations in two ways:
    1. Single organization: disable ORG_ID
    2. Multiple organizations: disable --file organizations.txt
    
    File format (one organization per line):
    org_id_1,Organization Name 1
    org_id_2,Organization Name 2
    # This is a comment line
    org_id_3  # Name will be empty for this one
    """
    token = os.getenv("SNYK_TOKEN")
    if not token:
        console.print("[red]❌ SNYK_TOKEN environment variable not set[/red]")
        raise typer.Exit(1)
    
    tool = SnykSASTTool(token)
    
    # Handle file input for multiple organizations
    if file_path:
        orgs = _read_orgs_from_file(file_path)
        
        # Process multiple organizations
        if not skip_confirm:
            console.print("\n[bold]Organizations to disable SAST for:[/bold]")
            for org in orgs:
                name_display = f" ({org['name']})" if org['name'] else ""
                console.print(f"- {org['id']}{name_display}")
            
            if not typer.confirm(f"\nAre you sure you want to disable SAST for {len(orgs)} organizations?"):
                console.print("[yellow]Operation cancelled by user.[/yellow]")
                return
        
        success_count = 0
        for org in orgs:
            try:
                tool.disable_sast(org['id'], org.get('name', ''))
                success_count += 1
            except Exception as e:
                console.print(f"[red]❌ Failed to disable SAST for {org['id']}: {str(e)}[/red]")
        
        console.print(f"\n[green]✓ Successfully disabled SAST for {success_count} organizations[/green]")
        if success_count < len(orgs):
            console.print(f"[red]❌ Failed to process {len(orgs) - success_count} organizations[/red]")
    
    # Handle single organization
    else:
        if not org_id:
            console.print("[red]❌ Organization ID is required when not using --file[/red]")
            raise typer.Exit(1)
        
        # Get organization name for better feedback
        org_name = ""
        try:
            org_url = f"https://api.snyk.io/rest/orgs/{org_id}?version=2024-10-15"
            response = tool.client._make_request('GET', org_url, headers=tool.client.headers_rest)
            if response.status_code == 200:
                org_data = response.json()
                org_name = org_data.get('data', {}).get('attributes', {}).get('name', '')
        except Exception as e:
            console.print(f"[yellow]⚠️  Could not fetch organization name: {str(e)}[/yellow]")
        
        tool.disable_sast(org_id, org_name)

def _get_projects_from_file(file_path: str) -> List[dict]:
    """Read project IDs and names from a file"""
    if not os.path.exists(file_path):
        console.print(f"[red]❌ File not found: {file_path}[/red]")
        raise typer.Exit(1)
    
    projects = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    parts = line.split(',')
                    if len(parts) >= 1:
                        project_id = parts[0].strip()
                        project_name = parts[1].strip() if len(parts) > 1 else ""
                        if project_id:  # Only add if project_id is not empty
                            projects.append({"id": project_id, "name": project_name})
        
        if not projects:
            console.print("[yellow]⚠️  No valid project entries found in the file[/yellow]")
            raise typer.Exit(1)
            
        return projects
    except Exception as e:
        console.print(f"[red]❌ Error reading file: {str(e)}[/red]")
        raise typer.Exit(1)

@app.command()
def delete_projects(
    org_id: str = typer.Argument(
        ...,
        help="Organization ID containing the projects",
        callback=_validate_org_id
    ),
    project_ids: List[str] = typer.Argument(
        None,
        help="Project IDs to delete (space-separated). Use --file to read from a file."
    ),
    file_path: str = typer.Option(
        None,
        "--file",
        "-f",
        help="Path to a file containing project IDs (and optionally names) to delete. Format: id,name (one per line)",
        callback=lambda x: x.strip() if x else None
    ),
    export_path: str = typer.Option(
        None,
        "--export",
        "-e",
        help="Export projects to a file before deletion",
        callback=lambda x: x.strip() if x else None
    ),
    skip_confirm: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation prompt"
    )
):
    """
    Delete SAST projects from an organization.
    
    You can specify projects in multiple ways:
    1. As command-line arguments: delete-projects ORG_ID PROJECT_ID1 PROJECT_ID2
    2. From a file: delete-projects ORG_ID --file projects.txt
    3. Delete all SAST projects: delete-projects ORG_ID
    
    File format (one project per line):
    project_id_1,Project Name 1
    project_id_2,Project Name 2
    # This is a comment line
    project_id_3  # Name will be empty for this one
    """
    token = os.getenv("SNYK_TOKEN")
    if not token:
        console.print("[red]❌ SNYK_TOKEN environment variable not set[/red]")
        raise typer.Exit(1)
    
    tool = SnykSASTTool(token)
    
    # Get organization name for better feedback
    org_name = f"organization {org_id}"
    try:
        org_url = f"https://api.snyk.io/rest/orgs/{org_id}?version=2024-10-15"
        response = tool.client._make_request('GET', org_url, headers=tool.client.headers_rest)
        if response.status_code == 200:
            org_data = response.json()
            org_name = org_data.get('data', {}).get('attributes', {}).get('name', org_name)
    except Exception as e:
        console.print(f"[yellow]⚠️  Could not fetch organization name: {str(e)}[/yellow]")
    
    # Handle file input
    if file_path:
        projects = _get_projects_from_file(file_path)
        project_ids = [p['id'] for p in projects]
    elif not project_ids:
        # If no project IDs provided, get all SAST projects
        console.print(f"[yellow]⚠️  No project IDs provided. Fetching all SAST projects for {org_name}...[/yellow]")
        sast_projects = tool.client.get_sast_projects(org_id)
        if not sast_projects:
            console.print("[green]✓ No SAST projects found to delete.[/green]")
            return
            
        projects = [{"id": p.get('id'), "name": p.get('name', 'Unnamed Project')} for p in sast_projects]
        project_ids = [p['id'] for p in projects if p['id']]
        
        if not project_ids:
            console.print("[yellow]⚠️  No valid project IDs found.[/yellow]")
            return
    else:
        # Convert command-line args to project list
        projects = [{"id": pid, "name": ""} for pid in project_ids]
    
    # Export projects if requested
    if export_path:
        try:
            with open(export_path, 'w') as f:
                f.write("# Project ID,Project Name\n")
                for project in projects:
                    f.write(f"{project['id']},{project.get('name', '')}\n")
            console.print(f"[green]✓ Projects exported to {export_path}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Error exporting projects: {str(e)}[/red]")
            if not typer.confirm("Continue with deletion?"):
                console.print("[yellow]Operation cancelled by user.[/yellow]")
                return
    
    # Show confirmation
    if not skip_confirm:
        console.print("\n[bold]Projects to delete:[/bold]")
        for project in projects:
            name_display = f" ({project['name']})" if project.get('name') else ""
            console.print(f"- {project['id']}{name_display}")
        
        if not typer.confirm(f"\nAre you sure you want to delete {len(project_ids)} projects from {org_name}?"):
            console.print("[yellow]Operation cancelled by user.[/yellow]")
            return
    
    # Perform deletion
    results = tool.delete_sast_projects(org_id, project_ids)
    
    # Show results
    console.print("\n[bold]Deletion Summary:[/bold]")
    console.print(f"[green]✓ Successfully deleted: {len(results['success'])} projects[/green]")
    if results["failed"]:
        console.print(f"[red]❌ Failed to delete: {len(results['failed'])} projects[/red]")
        console.print("Failed project IDs:", ", ".join(results["failed"]))

def main():
    app()

if __name__ == "__main__":
    main()
