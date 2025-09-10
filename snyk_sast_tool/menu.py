import os
import sys
import json
import glob
import typer
from typing import Optional, List, Dict, Any
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeElapsedColumn
from rich import box
from datetime import datetime
from pathlib import Path

from .core.api_client import SnykClient, SnykAPIError
from .cli import SnykSASTTool, _read_orgs_from_file


console = Console()

def _format_size(size_bytes: int) -> str:
    """Format file size in a human-readable format."""
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = 0
    while size_bytes >= 1024 and i < len(size_name) - 1:
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.1f}{size_name[i]}"

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
        console.print(Text.from_markup(f"[red]❌ {file_type.capitalize()} not found: [/red]"), Text(path, style="red"))

def show_main_menu() -> str:
    """Display the main menu and get user selection."""
    menu = """
[bold]Main Menu:[/bold]
1. 🔍 Audit SAST Settings
2. 🔄 Toggle SAST Scanning
3. 🗑️  Delete SAST Projects
4. 📊 View Reports
5. 🚪 Exit

[dim]Press Ctrl+C at any time to go back to the previous menu[/dim]
"""
    console.print(menu)
    try:
        return Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"])
    except KeyboardInterrupt:
        return "5"  # Exit on Ctrl+C

def is_valid_uuid(uuid_string):
    """Check if a string is a valid UUID."""
    import re
    uuid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.IGNORECASE)
    return bool(uuid_regex.match(uuid_string))

def show_audit_menu():
    """Run the audit workflow."""
    while True:
        print_header()
        console.print("[bold]🔍 Audit SAST Settings[/bold]\n")
        
        # Get group ID with validation
        while True:
            group_id = input("🏢 Enter Snyk Group ID (or 'back' to return): ").strip()
            
            if group_id.lower() == 'back':
                return
                
            if not group_id:
                console.print("[yellow]Group ID is required.[/yellow]")
                continue
                
            if not is_valid_uuid(group_id):
                console.print("[red]❌ Invalid Group ID format. It should be a valid UUID.[/red]")
                console.print("Example: 123e4567-e89b-12d3-a456-426614174000")
                continue
                
            break  # Valid UUID format
        
        output = Prompt.ask("📝 Output filename prefix", default="report")
        
        # Clear and simple format selection
        console.print("\n📊 Output Format:")
        console.print("1. Both JSON and Excel (default)")
        console.print("2. JSON only")
        console.print("3. Excel only")
        
        format_choice = Prompt.ask(
            "\nSelect format (1-3)",
            default="1",
            choices=["1", "2", "3"],
            show_choices=False
        )
        
        format_map = {
            "1": "both", 
            "2": "json", 
            "3": "excel"
        }
    
        try:
            # Run the audit
            token = get_snyk_token()
            if not token:
                console.print("[red]Error: No API token provided[/red]")
                input("\nPress Enter to continue...")
                return
                
            tool = SnykSASTTool(token)
            
            status_text = Text("Auditing organizations...")
            status_text.stylize("bold green")
            with console.status(status_text):
                audit_results = tool.audit_organizations(group_id)
                
                # Generate reports
                if format_map[format_choice] in ["json", "both"]:
                    json_file = f"{output}.json"
                    tool.report_generator.save_json(
                        tool.report_generator.prepare_audit_report(audit_results),
                        json_file
                    )
                    console.print(Text("✓ ", style="green") + Text(f"JSON report saved to {json_file}"))
            
                if format_map[format_choice] in ["excel", "both"]:
                    excel_file = f"{output}.xlsx"
                    tool.report_generator.save_excel(
                        tool.report_generator.prepare_flat_report(audit_results),
                        excel_file
                    )
                    console.print(Text("✓ ", style="green") + Text(f"Excel report saved to {excel_file}"))
        
        except SnykAPIError as e:
            error_msg = Text()
            error_msg.append("❌ ", style="red")
            error_msg.append("API Error: ")
            error_msg.append(str(e), style="red")
            console.print(error_msg)
            
            if "Group ID" in str(e):
                console.print("Please check the Group ID and try again.", style="yellow")
                
            input("\nPress Enter to continue...")
            return
            
        except Exception as e:
            error_msg = Text()
            error_msg.append("❌ ", style="red")
            error_msg.append("An error occurred: ")
            error_msg.append(str(e), style="red")
            console.print(error_msg)
            
            # Add debug info in development
            if os.getenv("DEBUG"):
                import traceback
                debug_info = Text()
                debug_info.append("\nDebug info:\n", style="dim")
                debug_info.append(traceback.format_exc(), style="dim")
                console.print(debug_info)
                
            input("\nPress Enter to continue...")
            return
        
        # Success - return to menu
        input("\nPress Enter to return to main menu...")
        return

def _find_audit_reports() -> List[dict]:
    """Find all JSON and Excel report files in the current and reports directory."""
    reports = []
    search_dirs = ['.']
    
    # Add 'reports' directory if it exists
    reports_dir = 'reports'
    if os.path.exists(reports_dir) and os.path.isdir(reports_dir):
        search_dirs.append(reports_dir)
    
    for directory in search_dirs:
        try:
            for f in os.listdir(directory):
                file_path = os.path.join(directory, f)
                if os.path.isfile(file_path) and (
                    (f.endswith('_audit.json') or f.startswith('report_') and f.endswith('.json')) or
                    (f.endswith('_audit.xlsx') or f.startswith('report_') and f.endswith('.xlsx'))
                ):
                    try:
                        stats = os.stat(file_path)
                        reports.append({
                            'name': file_path,
                            'created': stats.st_ctime,
                            'size': stats.st_size,
                            'type': 'JSON' if f.endswith('.json') else 'Excel'
                        })
                    except (OSError, Exception) as e:
                        console.print(Text(f"⚠️  Could not read file {file_path}: {str(e)}", style="yellow"))
                        continue
        except (OSError, Exception) as e:
            console.print(Text(f"⚠️  Could not search directory {directory}: {str(e)}", style="yellow"))
            continue
    
    # Sort by creation time, newest first
    return sorted(reports, key=lambda x: x['created'], reverse=True)

def format_size(size_bytes: int) -> str:
    """Convert file size to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def open_report(file_path: str):
    """Open a report file in the default application."""
    try:
        if not os.path.exists(file_path):
            console.print(Text(f"Report file not found: {file_path}", style="red"))
            return False
            
        if os.name == 'posix':  # macOS/Linux
            os.system(f'open "{file_path}"')
        else:  # Windows
            if file_path.lower().endswith('.xlsx'):
                os.system(f'start excel "{file_path}"')
            else:
                os.system(f'start "" "{file_path}"')
        return True
    except Exception as e:
        console.print(Text(f"❌ Failed to open report: {str(e)}", style="red"))
        return False

def _get_report_details(file_path: str) -> dict:
    """Get details about a report file."""
    try:
        stats = os.stat(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()
        file_type = 'JSON' if file_ext == '.json' else 'Excel' if file_ext == '.xlsx' else 'Unknown'
        
        # Try to read the file to check if it's a valid report
        is_valid = False
        try:
            with open(file_path, 'r' if file_type == 'JSON' else 'rb') as f:
                if file_type == 'JSON':
                    json.load(f)  # Will raise JSONDecodeError if invalid
                is_valid = True
        except:
            is_valid = False
            
        return {
            'name': file_path,
            'created': stats.st_ctime,
            'modified': stats.st_mtime,
            'size': stats.st_size,
            'type': file_type,
            'valid': is_valid
        }
    except Exception as e:
        return {
            'name': file_path,
            'error': str(e),
            'valid': False
        }

def _find_all_report_files() -> list:
    """Find all potential report files in the current directory and reports/ subdirectory."""
    report_files = []
    search_dirs = ['.', 'reports']
    
    for dir_path in search_dirs:
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            continue
            
        for ext in ('*.json', '*.xlsx'):
            try:
                full_path = os.path.join(dir_path, ext) if dir_path != '.' else ext
                report_files.extend(glob.glob(full_path))
            except Exception as e:
                console.print(f"[yellow]⚠️  Error searching for {ext} in {dir_path}: {str(e)}[/yellow]")
    
    # Get details for each file and sort by modification time (newest first)
    reports = []
    for file_path in report_files:
        report = _get_report_details(file_path)
        reports.append(report)
    
    return sorted(reports, key=lambda x: x.get('modified', 0), reverse=True)

def show_reports_menu():
    """Display available reports and allow viewing them."""
    while True:
        print_header()
        console.print("[bold]📊 View Reports[/bold]\n")
        
        reports = _find_all_report_files()
        
        if not reports:
            console.print(Text("No report files found.", style="yellow"))
            console.print("\nPlease run the 'Audit SAST Settings' command to generate reports.")
            input("\nPress Enter to return to main menu...")
            return
            
        # Create and display the reports table
        table = Table(box=box.ROUNDED, header_style="bold magenta", show_lines=False)
        table.add_column("#", width=4, justify="right")
        table.add_column("Status", width=8, justify="center")
        table.add_column("Filename", width=40, overflow="ellipsis")
        table.add_column("Type", width=8, justify="center")
        table.add_column("Modified", width=20)
        table.add_column("Size", width=10, justify="right")
        
        valid_reports = []
        
        for i, report in enumerate(reports, 1):
            try:
                report_name = os.path.basename(report['name'])
                modified = datetime.fromtimestamp(report.get('modified', 0)).strftime('%Y-%m-%d %H:%M')
                size = _format_size(report.get('size', 0))
                file_type = report.get('type', '?')
                is_valid = report.get('valid', False)
                
                if is_valid:
                    valid_reports.append(report)
                
                status_icon = "✅" if is_valid else "❌"
                status_text = Text(status_icon, style="green" if is_valid else "red")
                
                table.add_row(
                    str(i),
                    status_text,
                    Text(report_name, style="cyan"),
                    Text(file_type, style="yellow"),
                    modified,
                    size
                )
            except Exception as e:
                console.print(f"[red]Error processing report {i}: {str(e)}[/red]")
        
        console.print(table)
        
        # Show summary
        total = len(reports)
        valid = len(valid_reports)
        invalid = total - valid
        
        console.print(f"\n[bold]Summary:[/bold] {valid} valid, {invalid} invalid, {total} total")
        
        if invalid > 0:
            console.print("\n[bold]Note:[/bold] Some reports could not be read. Check file permissions or file format.")
        
        # Add options
        console.print("\n[bold]Options:[/bold]")
        console.print("1. View a report")
        console.print("2. Refresh list")
        console.print("3. Back to main menu\n")
        
        choice = input("Select an option [3]: ").strip() or "3"
        
        if choice == "1" and valid_reports:
            try:
                report_num = int(input(f"\nEnter report number (1-{len(reports)}): "))
                if 1 <= report_num <= len(reports):
                    selected_report = reports[report_num - 1]
                    if selected_report.get('valid', False):
                        open_report(selected_report['name'])
                    else:
                        console.print("\n[red]❌ Cannot open an invalid report. Please select a valid report.[/red]")
                        input("\nPress Enter to continue...")
                else:
                    console.print("\n[red]❌ Invalid report number.[/red]")
                    input("\nPress Enter to continue...")
            except ValueError:
                console.print("\n[red]❌ Please enter a valid number.[/red]")
                input("\nPress Enter to continue...")
        elif choice == "2":
            continue  # Refresh the list
        elif choice == "3" or choice.lower() in ['back', 'b']:
            return
        else:
            console.print("\n[red]❌ Invalid option. Please try again.[/red]")
            input("\nPress Enter to continue...")
            try:
                report_name = os.path.basename(report['name'])
                created = datetime.fromtimestamp(report['created']).strftime('%Y-%m-%d %H:%M')
                table.add_row(
                    str(i),
                    Text(report_name, style="cyan"),
                    Text(report['type'], style="yellow"),
                    created,
                    format_size(report['size'])
                )
            except Exception as e:
                console.print(Text(f"⚠️  Error processing report {i}: {str(e)}", style="red"))
                continue
        
        if table.rows:
            console.print(table)
            
            # Add options
            console.print("\n[bold]Options:[/bold]")
            console.print("1. Open a report")
            console.print("2. Refresh list")
            console.print("3. Return to main menu\n")
            
            choice = input("Select an option [3]: ").strip() or "3"
            
            if choice == "1" and reports:
                try:
                    report_num = int(input(f"\nEnter report number (1-{len(reports)}): "))
                    if 1 <= report_num <= len(reports):
                        open_report(reports[report_num - 1]['name'])
                except (ValueError, IndexError):
                    console.print(Text("Invalid selection.", style="red"))
                    input("\nPress Enter to continue...")
            elif choice == "2":
                continue  # Refresh the list
            elif choice == "3" or choice.lower() in ['back', 'b']:
                return
            else:
                console.print(Text("Invalid option. Please try again.", style="red"))
                input("\nPress Enter to continue...")
        else:
            console.print(Text("No valid reports found to display.", style="yellow"))
            input("\nPress Enter to return to main menu...")
            return

def show_sast_toggle_menu():
    """Run the SAST toggle workflow (enable/disable)."""
    while True:
        print_header()
        console.print("[bold]🔄 Toggle SAST Scanning[/bold]\n")
        
        # First, ask whether to enable or disable
        console.print("[bold]🔘 Select action:[/bold]")
        console.print("1. Enable SAST Scanning")
        console.print("2. Disable SAST Scanning")
        console.print("3. Return to main menu\n")
        
        action_choice = input("Select an option [3]: ").strip() or "3"
        
        if action_choice == "3":
            return
            
        if action_choice not in ["1", "2"]:
            console.print(Text("⚠️  Invalid choice. Please try again.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
            
        enable_sast = (action_choice == "1")  # True for enable, False for disable
        action_text = "enable" if enable_sast else "disable"
        
        # Then proceed with organization selection
        while True:
            print_header()
            action_title = 'Enable' if enable_sast else 'Disable'
            console.print(f"[bold]{'🟢' if enable_sast else '🔴'} {action_title} SAST Scanning[/bold]\n")
            
            console.print("[bold]🔍 Select input method:[/bold]")
            console.print("1. Single organization")
            console.print("2. Multiple organizations from file")
            console.print("3. Back to main menu\n")
            
            method_choice = input("Select an option [3]: ").strip() or "3"
            
            if method_choice == "3":
                return
                
            if method_choice not in ["1", "2"]:
                console.print(Text("Invalid choice. Please try again.", style="red"))
                input("\nPress Enter to continue...")
                continue
                
            token = get_snyk_token()
            if not token:
                console.print(Text("❌ No API token provided", style="red"))
                input("\nPress Enter to continue...")
                continue
                
            tool = SnykSASTTool(token)
            orgs = []
            
            if method_choice == "1":
                # Check for existing audit reports
                audit_reports = _find_audit_reports()
                
                if not audit_reports:
                    console.print(Text("No audit reports found. Please run an audit first.", style="yellow"))
                    input("\nPress Enter to continue...")
                    continue
                    
                console.print("\n[bold]📋 Select an audit report:[/bold]")
                for i, report in enumerate(audit_reports, 1):
                    # Format the report display
                    report_name = os.path.basename(report['name'])
                    report_date = datetime.fromtimestamp(report['created']).strftime('%Y-%m-%d %H:%M')
                    report_size = format_size(report['size'])
                    console.print(f"{i}. [bold]{report_name}[/bold] ({report['type']}, {report_size}, {report_date})")
                console.print(f"\n{len(audit_reports) + 1}. ↩️ Back to main menu")
                
                try:
                    report_choice = int(input("\nSelect a report [1]: ") or "1")
                    if report_choice == len(audit_reports) + 1:
                        return
                    if report_choice < 1 or report_choice > len(audit_reports):
                        raise ValueError
                except (ValueError, IndexError):
                    console.print(Text("Invalid selection. Please try again.", style="red"))
                    input("\nPress Enter to continue...")
                    continue
                    
                selected_report = audit_reports[report_choice - 1]
                report_file = selected_report['name']
                try:
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    orgs = [{"id": org["id"], "name": sanitize_for_rich(org.get("name", ""))} 
                           for org in report_data.get("organizations", [])]
                except json.JSONDecodeError as e:
                    console.print(Text(f"❌ Error reading report file: Invalid JSON format - {str(e)}", style="red"))
                    input("\nPress Enter to continue...")
                    continue
                except Exception as e:
                    console.print(Text(f"❌ Error reading report file: {str(e)}", style="red"))
                    input("\nPress Enter to continue...")
                    continue
            
            elif method_choice == "2":
                # Multiple organizations from file
                file_path = get_file_path("Enter path to organizations file (JSON or XLSX): ")
                if not file_path:
                    continue
                    
                try:
                    orgs = _read_orgs_from_file(file_path)
                    if not orgs:
                        console.print(Text("No valid organizations found in the file.", style="yellow"))
                        input("\nPress Enter to continue...")
                        continue
                except Exception as e:
                    console.print(Text(f"❌ Error reading file: {str(e)}", style="red"))
                    input("\nPress Enter to continue...")
                    continue
            
            if not orgs:
                console.print(Text("No organizations selected.", style="yellow"))
                input("\nPress Enter to continue...")
                continue
            
            # Show confirmation
            console.print(f"\n[bold]🔍 The following {len(orgs)} organizations will have SAST scanning {action_text}d:[/bold]")
            for org in orgs[:5]:
                console.print(f"- {org.get('name', 'Unnamed')} (ID: {org['id']})")
            if len(orgs) > 5:
                console.print(f"- ... and {len(orgs) - 5} more")
            
            confirm_msg = f"\nAre you sure you want to {action_text} SAST for {len(orgs)} organizations?"
            if not Confirm.ask(confirm_msg, default=False):
                console.print(Text("⚠️  Operation cancelled.", style="yellow"))
                input("\nPress Enter to continue...")
                continue
            
            # Process organizations
            success = 0
            try:
                with Progress(
                    SpinnerColumn(),
                    "•",
                    "[progress.description]{task.description}",
                    BarColumn(bar_width=None),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    "•",
                    TimeElapsedColumn(),
                    console=console,
                    transient=True
                ) as progress:
                    task = progress.add_task(
                        f"{'Enabling' if enable_sast else 'Disabling'} SAST...",
                        total=len(orgs)
                    )
                    
                    for org in orgs:
                        try:
                            org_id = org['id']
                            org_name = org.get('name', org_id)
                            
                            # Update progress
                            progress.update(
                                task,
                                description=f"{'Enabling' if enable_sast else 'Disabling'} {org_name[:20]}..." \
                                          f"{' ' * (20 - min(20, len(org_name)))}"
                            )
                            
                            # Toggle SAST
                            if enable_sast:
                                result = tool.enable_sast(org_id, org_name)
                            else:
                                result = tool.disable_sast(org_id, org_name)
                                
                            if result:
                                success += 1
                                
                        except Exception as e:
                            error_msg = Text("❌ ", style="red")
                            error_msg.append(f"Error processing {org.get('name', org_id)}: {str(e)}")
                            console.print(error_msg)
                        
                        progress.advance(task)
            
            except Exception as e:
                console.print(Text(f"❌ An error occurred: {str(e)}", style="red"))
                input("\nPress Enter to continue...")
            else:
                # Show results
                console.print(f"\n✅ Successfully {action_text}d SAST for {success}/{len(orgs)} organizations.")
                input("\nPress Enter to continue...")

def show_delete_projects_menu():
    """Run the delete projects workflow."""
    while True:  # Main menu loop
        print_header()
        console.print("[bold]🗑️  Delete SAST Projects[/bold]\n")
        
        # Ask for organization selection method
        console.print("[bold]🔍 Select organization input method:[/bold]")
        console.print("1. Single organization ID")
        console.print("2. Multiple organizations from file")
        console.print("3. Back to main menu\n")
        
        method_choice = input("Select an option [3]: ").strip() or "3"
        
        if method_choice == "3":
            return
            
        if method_choice not in ["1", "2"]:
            console.print(Text("⚠️  Invalid choice. Please try again.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
            
        orgs = []
        
        if method_choice == "1":
            # Single organization
            org_id = get_org_id()
            if not org_id:
                continue
            orgs = [{"id": org_id, "name": ""}]
            
        elif method_choice == "2":
            # Multiple organizations from file
            file_path = get_file_path("Enter path to organizations file (JSON or XLSX): ")
            if not file_path:
                continue
                
            try:
                orgs = _read_orgs_from_file(file_path)
                if not orgs:
                    console.print(Text("No valid organizations found in the file.", style="yellow"))
                    input("\nPress Enter to continue...")
                    continue
            except Exception as e:
                console.print(Text(f"❌ Error reading file: {str(e)}", style="red"))
                input("\nPress Enter to continue...")
                continue
        
        if not orgs:
            console.print(Text("No organizations selected.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
            
        token = get_snyk_token()
        if not token:
            continue
            
        tool = SnykSASTTool(token)
        all_projects = {}
        
        # Get projects for all selected organizations
        with console.status(Text("Fetching projects...", style="bold green")) as status:
            for org in orgs:
                org_id = org['id']
                org_name = org.get('name', org_id)
                try:
                    projects = tool.client.get_sast_projects(org_id)
                    if projects:
                        all_projects[org_name] = projects
                except Exception as e:
                    console.print(Text(f"❌ Error fetching projects for {org_name}: {str(e)}", style="red"))
        
        if not all_projects:
            console.print(Text("No SAST projects found in the selected organizations.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
    
        # Show projects by organization
        project_map = {}
        total_projects = 0
        
        for org_name, projects in all_projects.items():
            console.print(Text(f"\n[bold]Organization: {org_name}[/bold]"))
            console.print(Text(f"Found {len(projects)} SAST projects:"))
            
            org_projects = []
            for i, proj in enumerate(projects[:10], 1):
                proj_id = proj.get('id', '')
                proj_name = proj.get('name', 'Unnamed')
                console.print(f"  {i}. {proj_name} ({proj_id})")
                org_projects.append({"id": proj_id, "name": proj_name})
                
            if len(projects) > 10:
                console.print(f"  ... and {len(projects) - 10} more")
                
            project_map[org_name] = org_projects
            total_projects += len(projects)
        
        if total_projects == 0:
            console.print(Text("No projects to delete.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
        
        # Get action
        console.print("\n[bold]Select action:[/bold]")
        console.print("1. Delete all projects")
        console.print("2. Select specific projects to delete")
        console.print("3. Back to organization selection\n")
        
        action = input("Select an option [3]: ").strip() or "3"
        
        if action == "3":
            continue
            
        if action not in ["1", "2"]:
            console.print(Text("⚠️  Invalid choice. Please try again.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
        
        project_ids = []
        selected_orgs = []
        
        if action == "1":  # Delete all
            if not Confirm.ask(Text.from_markup("\n⚠️  Delete ALL projects? This cannot be undone!"), default=False):
                console.print(Text("Operation cancelled.", style="yellow"))
                input("\nPress Enter to continue...")
                continue
                
            for org_name, projects in all_projects.items():
                project_ids.extend([p['id'] for p in projects])
                selected_orgs.append(org_name)
                
        elif action == "2":  # Select projects
            console.print("\n[bold]Select organizations to include:[/bold]")
            org_list = list(all_projects.keys())
            
            for i, org_name in enumerate(org_list, 1):
                console.print(f"{i}. {org_name} ({len(all_projects[org_name])} projects)")
            
            console.print(f"{len(org_list) + 1}. Select all organizations")
            console.print(f"{len(org_list) + 2}. Cancel\n")
            
            try:
                selected = input("Enter organization numbers (comma-separated): ").strip()
                if not selected:
                    console.print(Text("No organizations selected.", style="yellow"))
                    input("\nPress Enter to continue...")
                    continue
                    
                if selected == str(len(org_list) + 1):  # Select all
                    selected_orgs = org_list
                elif selected == str(len(org_list) + 2):  # Cancel
                    continue
                else:
                    indices = [int(i.strip()) - 1 for i in selected.split(",")]
                    selected_orgs = [org_list[i] for i in indices if 0 <= i < len(org_list)]
                    
                if not selected_orgs:
                    console.print(Text("No valid organizations selected.", style="yellow"))
                    input("\nPress Enter to continue...")
                    continue
                    
                # Now select projects from selected orgs
                console.print("\n[bold]Select projects to delete:[/bold]")
                project_choices = []
                
                for org_name in selected_orgs:
                    projects = all_projects[org_name]
                    console.print(f"\n[bold]{org_name}:[/bold]")
                    for i, proj in enumerate(projects, 1):
                        proj_id = proj['id']
                        proj_name = proj['name']
                        project_choices.append((org_name, proj_id, proj_name))
                        console.print(f"  {len(project_choices)}. {proj_name} ({proj_id})")
                
                console.print(f"\n{len(project_choices) + 1}. Select all projects")
                console.print(f"{len(project_choices) + 2}. Cancel\n")
                
                selected = input("Enter project numbers to delete (comma-separated): ").strip()
                if not selected:
                    console.print(Text("No projects selected.", style="yellow"))
                    input("\nPress Enter to continue...")
                    continue
                    
                if selected == str(len(project_choices) + 1):  # Select all
                    project_ids = [p[1] for p in project_choices]
                elif selected == str(len(project_choices) + 2):  # Cancel
                    continue
                else:
                    try:
                        indices = [int(i.strip()) - 1 for i in selected.split(",")]
                        project_ids = [project_choices[i][1] for i in indices if 0 <= i < len(project_choices)]
                    except (ValueError, IndexError):
                        console.print(Text("❌ Invalid selection.", style="red"))
                        input("\nPress Enter to continue...")
                        continue
                        
            except (ValueError, IndexError) as e:
                console.print(Text(f"❌ Error: {str(e)}", style="red"))
                input("\nPress Enter to continue...")
                continue
    
        # Confirm and delete
        if not project_ids:
            console.print(Text("No projects selected.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
        
        delete_confirm = Text()
        delete_confirm.append("\n⚠️  Will delete ", style="bold red")
        delete_confirm.append(str(len(project_ids)), style="bold red")
        delete_confirm.append(" projects from ", style="bold red")
        delete_confirm.append(str(len(selected_orgs)) if selected_orgs else str(len(orgs)), style="bold red")
        delete_confirm.append(" organization(s). This cannot be undone!", style="bold red")
        console.print(delete_confirm)
        
        if not Confirm.ask("\nAre you sure you want to continue?", default=False):
            console.print(Text("Operation cancelled.", style="yellow"))
            input("\nPress Enter to continue...")
            continue
        
        # Delete projects
        success = 0
        errors = []
        
        with Progress(
            SpinnerColumn(),
            "•",
            "[progress.description]{task.description}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Deleting projects...", total=len(project_ids))
            
            # Group projects by organization for more efficient deletion
            org_projects = {}
            for org in orgs:
                org_projects[org['id']] = []
                
            # Map project IDs to their organizations
            for pid in project_ids:
                for org in orgs:
                    org_projects[org['id']].append(pid)
            
            # Delete projects by organization
            for org_id, pids in org_projects.items():
                if not pids:
                    continue
                    
                for pid in pids:
                    try:
                        tool.client.delete_project(org_id, pid)
                        success += 1
                    except Exception as e:
                        errors.append(f"Error deleting project {pid}: {str(e)}")
                    finally:
                        progress.advance(task)
        
        # Show results
        if errors:
            console.print("\n[bold red]⚠️  The following errors occurred:[/bold red]")
            for error in errors:
                console.print(f"  • {error}")
        
        success_msg = Text()
        success_msg.append("\n✓ ", style="green")
        success_msg.append(f"Successfully deleted {success}/{len(project_ids)} projects.", style="green")
        console.print(success_msg)
        
        if not Confirm.ask("\nDelete more projects?", default=False):
            break
        
        # Clear the screen for the next iteration
        clear_screen()

def main():
    """Main menu loop."""
    while True:
        try:
            choice = show_main_menu()
            
            if choice == "1":
                show_audit_menu()
            elif choice == "2":
                show_sast_toggle_menu()
            elif choice == "3":
                show_delete_projects_menu()
            elif choice == "4":
                show_reports_menu()
            elif choice == "5":
                console.print("\n👋 Goodbye!")
                break
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Returning to main menu...[/yellow]")
            continue
        except Exception as e:
            error_msg = Text()
            error_msg.append("\n❌ ", style="red")
            error_msg.append("An error occurred: ")
            error_msg.append(str(e), style="red")
            console.print(error_msg)
            
            if os.getenv("DEBUG"):
                import traceback
                debug_info = Text()
                debug_info.append("\nDebug info:\n", style="dim")
                debug_info.append(traceback.format_exc(), style="dim")
                console.print(debug_info)
                
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
