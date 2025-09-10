import os
import sys
import typer
from typing import Optional, List
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table

from .core.api_client import SnykClient, SnykAPIError
from .cli import SnykSASTTool, _read_orgs_from_file

console = Console()

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Print the application header."""
    clear_screen()
    console.print(
        Panel.fit(
            "[bold blue]Snyk SAST Management Tool[/bold blue]",
            border_style="blue"
        )
    )

def get_snyk_token() -> str:
    """Get Snyk API token from environment or prompt."""
    token = os.getenv("SNYK_TOKEN")
    if not token:
        token = Prompt.ask("🔑 Enter your Snyk API token", password=True)
    return token

def get_group_id() -> str:
    """Prompt for Snyk Group ID."""
    return Prompt.ask("🏢 Enter Snyk Group ID")

def get_org_id() -> str:
    """Prompt for Snyk Organization ID."""
    return Prompt.ask("🏛️  Enter Snyk Organization ID")

def get_file_path(prompt: str, file_type: str = "file") -> str:
    """Prompt for file path with validation."""
    while True:
        path = Prompt.ask(f"📂 {prompt}")
        if os.path.exists(path):
            return path
        console.print(f"[red]❌ {file_type.capitalize()} not found: {path}[/red]")

def show_main_menu() -> str:
    """Display the main menu and get user selection."""
    menu = """
[bold]Main Menu:[/bold]
1. 🔍 Audit SAST Settings
2. 🚫 Disable SAST
3. 🗑️  Delete SAST Projects
4. 📊 View Reports
5. 🚪 Exit
"""
    console.print(menu)
    return Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"])

def show_audit_menu():
    """Run the audit workflow."""
    print_header()
    console.print("[bold]🔍 Audit SAST Settings[/bold]\n")
    
    group_id = get_group_id()
    output = Prompt.ask("📝 Output filename prefix", default="report")
    
    format_choice = Prompt.ask(
        "📊 Output format",
        choices=["1", "2", "3"],
        default="1",
        show_choices=False,
        show_default=False
    )
    
    format_map = {"1": "both", "2": "json", "3": "excel"}
    
    # Run the audit
    token = get_snyk_token()
    tool = SnykSASTTool(token)
    
    with console.status("[bold green]Running audit..."):
        audit_results = tool.audit_organizations(group_id)
        
        # Generate reports
        if format_map[format_choice] in ["json", "both"]:
            json_file = f"{output}.json"
            tool.report_generator.save_json(
                tool.report_generator.prepare_audit_report(audit_results),
                json_file
            )
            console.print(f"[green]✓ JSON report saved to {json_file}[/green]")
        
        if format_map[format_choice] in ["excel", "both"]:
            excel_file = f"{output}.xlsx"
            tool.report_generator.save_excel(
                tool.report_generator.prepare_flat_report(audit_results),
                excel_file
            )
            console.print(f"[green]✓ Excel report saved to {excel_file}[/green]")
    
    input("\nPress Enter to continue...")

def show_disable_menu():
    """Run the disable SAST workflow."""
    print_header()
    console.print("[bold]🚫 Disable SAST[/bold]\n")
    
    # Get input method
    input_method = Prompt.ask(
        "Select input method",
        choices=["1", "2"],
        default="1",
        show_choices=False
    )
    
    token = get_snyk_token()
    tool = SnykSASTTool(token)
    
    if input_method == "1":
        # Single organization
        org_id = get_org_id()
        orgs = [{"id": org_id, "name": ""}]
    else:
        # From file
        file_path = get_file_path("Enter path to organizations file")
        orgs = _read_orgs_from_file(file_path)
    
    # Show confirmation
    console.print(f"\n[bold]Organizations to process:[/bold] {len(orgs)}")
    for org in orgs[:5]:  # Show first 5
        console.print(f"- {org['id']} ({org.get('name', 'No name')})")
    if len(orgs) > 5:
        console.print(f"- ... and {len(orgs) - 5} more")
    
    if not Confirm.ask("\nContinue with disabling SAST?", default=False):
        console.print("[yellow]Operation cancelled.[/yellow]")
        return
    
    # Process organizations
    success = 0
    with console.status("[bold green]Disabling SAST..."):
        for org in orgs:
            try:
                tool.disable_sast(org['id'], org.get('name', ''))
                success += 1
            except Exception as e:
                console.print(f"[red]❌ Error processing {org['id']}: {str(e)}[/red]")
    
    console.print(f"\n[green]✓ Successfully disabled SAST for {success}/{len(orgs)} organizations[/green]")
    input("\nPress Enter to continue...")

def show_delete_projects_menu():
    """Run the delete projects workflow."""
    print_header()
    console.print("[bold]🗑️  Delete SAST Projects[/bold]\n")
    
    org_id = get_org_id()
    token = get_snyk_token()
    tool = SnykSASTTool(token)
    
    # Get projects
    with console.status("[bold green]Fetching projects..."):
        projects = tool.client.get_sast_projects(org_id)
    
    if not projects:
        console.print("[yellow]No SAST projects found.[/yellow]")
        input("\nPress Enter to continue...")
        return
    
    # Show projects
    console.print(f"\n[bold]Found {len(projects)} SAST projects:[/bold]")
    for i, proj in enumerate(projects[:10], 1):
        console.print(f"{i}. {proj.get('name', 'Unnamed')} ({proj.get('id')})")
    if len(projects) > 10:
        console.print(f"... and {len(projects) - 10} more")
    
    # Get action
    action = Prompt.ask(
        "\nSelect action",
        choices=["1", "2", "3"],
        default="1",
        show_choices=False
    )
    
    if action == "1":  # Delete all
        if not Confirm.ask("\nDelete ALL projects? This cannot be undone!", default=False):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
        project_ids = [p['id'] for p in projects]
    elif action == "2":  # Select projects
        # Simplified for CLI - in a real app, you'd want a better multi-select
        selected = Prompt.ask("\nEnter project numbers to delete (comma-separated)")
        try:
            indices = [int(i.strip()) - 1 for i in selected.split(",")]
            project_ids = [projects[i]['id'] for i in indices if 0 <= i < len(projects)]
        except (ValueError, IndexError):
            console.print("[red]❌ Invalid selection[/red]")
            return
    else:  # From file
        file_path = get_file_path("Enter path to projects file")
        try:
            project_objs = _read_orgs_from_file(file_path)  # Reuse the same function
            project_ids = [p['id'] for p in project_objs]
        except Exception as e:
            console.print(f"[red]❌ Error reading file: {str(e)}[/red]")
            return
    
    # Confirm and delete
    if not project_ids:
        console.print("[yellow]No projects selected.[/yellow]")
        return
    
    console.print(f"\n[bold]Will delete {len(project_ids)} projects.[/bold]")
    if not Confirm.ask("\nContinue?", default=False):
        console.print("[yellow]Operation cancelled.[/yellow]")
        return
    
    # Delete projects
    success = 0
    with console.status("[bold green]Deleting projects..."):
        for pid in project_ids:
            try:
                tool.client.delete_project(org_id, pid)
                success += 1
            except Exception as e:
                console.print(f"[red]❌ Error deleting project {pid}: {str(e)}[/red]")
    
    console.print(f"\n[green]✓ Successfully deleted {success}/{len(project_ids)} projects[/green]")
    input("\nPress Enter to continue...")

def main():
    """Main menu loop."""
    while True:
        try:
            print_header()
            choice = show_main_menu()
            
            if choice == "1":
                show_audit_menu()
            elif choice == "2":
                show_disable_menu()
            elif choice == "3":
                show_delete_projects_menu()
            elif choice == "4":
                console.print("\n[bold]View Reports[/bold]")
                console.print("This feature is not yet implemented.")
                input("\nPress Enter to continue...")
            elif choice == "5":
                console.print("\n[blue]Goodbye! 👋[/blue]")
                sys.exit(0)
                
        except KeyboardInterrupt:
            if Confirm.ask("\nAre you sure you want to exit?"):
                console.print("\n[blue]Goodbye! 👋[/blue]")
                sys.exit(0)
        except Exception as e:
            console.print(f"\n[red]❌ An error occurred: {str(e)}[/red]")
            if os.getenv("DEBUG"):
                import traceback
                console.print(traceback.format_exc())
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
