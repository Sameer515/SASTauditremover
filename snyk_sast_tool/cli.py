import os
import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from core.api_client import SnykClient, SnykAPIError
from utils.report_generator import ReportGenerator

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
                progress.update(task, description=f"[cyan]Checking {org.get('name')}...")
                
                settings = self.client.get_sast_settings(org['id'])
                org_data = {
                    "id": org['id'],
                    "name": org['name'],
                    "settings": settings
                }
                
                if settings and settings.get("sast_enabled"):
                    org_data["sast_projects"] = self.client.get_sast_projects(org['id'])
                    audit_results["sast_enabled_orgs"].append(org_data)
                    console.print(f"[green]✓[/green] {org['name']}: SAST Enabled")
                else:
                    audit_results["sast_disabled_orgs"].append(org_data)
                    console.print(f"[yellow]•[/yellow] {org['name']}: SAST Disabled")
                
                progress.update(task, advance=1, completed=20+i)
            
            return audit_results
    
    def disable_sast(self, org_id: str, org_name: str = "") -> bool:
        """Disable SAST for a specific organization"""
        try:
            console.print(f"[yellow]⚠️  Attempting to disable SAST for {org_name or org_id}...[/yellow]")
            success = self.client.disable_sast(org_id)
            if success:
                console.print(f"[green]✓ Successfully disabled SAST for {org_name or org_id}[/green]")
            return success
        except SnykAPIError as e:
            console.print(f"[red]❌ Failed to disable SAST: {str(e)}[/red]")
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
    project_ids: List[str] = typer.Argument(..., help="List of project IDs to delete")
):
    """Delete SAST projects from an organization"""
    token = os.getenv("SNYK_TOKEN")
    if not token:
        console.print("[red]❌ SNYK_TOKEN environment variable not set[/red]")
        raise typer.Exit(1)
    
    if not project_ids:
        console.print("[yellow]⚠️  No project IDs provided.[/yellow]")
        return
    
    tool = SnykSASTTool(token)
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
