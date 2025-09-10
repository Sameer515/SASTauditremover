import requests
import json
import os
import pandas as pd
from datetime import datetime

# --- Configuration ---
SNYK_TOKEN = os.getenv("SNYK_TOKEN")
API_V1_BASE_URL = "https://api.snyk.io/v1"
API_REST_BASE_URL = "https://api.snyk.io/rest"
API_VERSION = "2024-05-24" # Use a recent, stable REST API version

# --- API Headers ---
HEADERS_V1 = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/json"
}
HEADERS_REST = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json"
}

def get_json_filename():
    """Asks the user for a JSON filename, providing a default."""
    today_date = datetime.now().strftime("%Y-%m-%d")
    default_name = f"snyk_sast_report_{today_date}.json"
    filename = input(f"Enter the JSON filename for the report (default: {default_name}): ").strip()
    return filename if filename else default_name

def get_all_orgs_in_group(group_id):
    """Fetches all organizations for a given Snyk Group ID."""
    url = f"{API_V1_BASE_URL}/group/{group_id}/orgs"
    print(f"\nFetching organizations for Group ID: {group_id}...")
    try:
        response = requests.post(url, headers=HEADERS_V1)
        response.raise_for_status()
        orgs = response.json().get("orgs", [])
        print(f"✅ Found {len(orgs)} organizations.")
        return orgs
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching organizations: {e}")
        return None

def get_sast_settings(org_id):
    """Retrieves the SAST settings for a single organization."""
    url = f"{API_REST_BASE_URL}/orgs/{org_id}/settings/sast?version={API_VERSION}"
    try:
        response = requests.get(url, headers=HEADERS_REST)
        response.raise_for_status()
        return response.json().get("data", {}).get("attributes", {})
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404: # Not found can mean not configured
            return {"sast_enabled": False}
        print(f"❌ HTTP Error checking SAST settings for Org {org_id}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Request Error checking SAST settings for Org {org_id}: {e}")
        return None

def disable_sast_for_org(org_id):
    """Disables Snyk Code (SAST) for a specified organization."""
    url = f"{API_REST_BASE_URL}/orgs/{org_id}/settings/sast?version={API_VERSION}"
    payload = {
        "data": {
            "type": "sast_settings",
            "attributes": { "sast_enabled": False }
        }
    }
    try:
        response = requests.patch(url, headers=HEADERS_REST, json=payload)
        response.raise_for_status()
        print(f"✅ SAST successfully disabled for Org ID: {org_id}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to disable SAST for Org ID {org_id}: {e}")
        return False

def get_sast_projects(org_id):
    """Fetches all SAST projects for a given organization."""
    sast_projects = []
    url = f"{API_REST_BASE_URL}/orgs/{org_id}/projects?version={API_VERSION}&limit=100"
    try:
        while url:
            response = requests.get(url, headers=HEADERS_REST)
            response.raise_for_status()
            data = response.json()
            projects = data.get("data", [])
            for project in projects:
                if project.get("attributes", {}).get("type") == "sast":
                    sast_projects.append({
                        "id": project.get("id"),
                        "name": project.get("attributes", {}).get("name")
                    })
            url = data.get("links", {}).get("next")
    except requests.exceptions.RequestException as e:
        print(f"  -> ❌ Could not fetch projects for Org ID {org_id}: {e}")
    return sast_projects

def delete_sast_project(org_id, project_id):
    """Deletes a specific project from an organization."""
    url = f"{API_REST_BASE_URL}/orgs/{org_id}/projects/{project_id}?version={API_VERSION}"
    try:
        response = requests.delete(url, headers=HEADERS_REST)
        response.raise_for_status() # Raises exception for 4xx/5xx responses
        print(f"✅ Project {project_id} deleted successfully from Org {org_id}.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to delete project {project_id}: {e}")
        return False

def main():
    """Main function to run the interactive script."""
    if not SNYK_TOKEN:
        print("❌ FATAL: SNYK_TOKEN environment variable not set. Exiting.")
        return

    print("--- Snyk SAST Management Tool ---")

    # Determine scope: Group or single Org
    scope_choice = input("Should this action be performed on a whole Group or a single Org? (group/org): ").lower().strip()

    if scope_choice == 'group':
        group_id = input("Enter your Snyk Group ID: ").strip()
        organizations = get_all_orgs_in_group(group_id)
    elif scope_choice == 'org':
        org_id = input("Enter your Snyk Organization ID: ").strip()
        org_name = input("Enter the Organization Name (for display): ").strip()
        organizations = [{"id": org_id, "name": org_name}]
    else:
        print("❌ Invalid choice. Please enter 'group' or 'org'.")
        return

    if not organizations:
        print("No organizations to process. Exiting.")
        return

    # --- Step 1: Audit and Display ---
    print("\n--- 🔍 STEP 1: AUDITING SAST STATUS ---")
    sast_enabled_orgs = []
    for org in organizations:
        settings = get_sast_settings(org['id'])
        if settings and settings.get("sast_enabled"):
            print(f"🟢 SAST is ENABLED for '{org['name']}' ({org['id']})")
            sast_enabled_orgs.append(org)
        else:
            print(f"⚪ SAST is DISABLED for '{org['name']}' ({org['id']})")
    
    if not sast_enabled_orgs:
        print("\nNo organizations with SAST enabled were found. Nothing to do.")
        return
        
    print("\n--- Orgs with SAST Enabled ---")
    for org in sast_enabled_orgs:
        print(f"  - {org['name']} (ID: {org['id']})")

    # --- Step 2: Disable SAST (Optional) ---
    print("\n--- ⚙️ STEP 2: DISABLE SAST (OPTIONAL) ---")
    if input("Do you want to disable SAST for one or more of these orgs? (y/n): ").lower() == 'y':
        org_ids_to_disable = input("Enter Org IDs to disable, separated by commas: ").strip()
        for org_id in [oid.strip() for oid in org_ids_to_disable.split(',')]:
            if any(o['id'] == org_id for o in sast_enabled_orgs):
                org_name = next((o['name'] for o in sast_enabled_orgs if o['id'] == org_id), "Unknown")
                confirm = input(f"🚨 WARNING: You are about to disable SAST for '{org_name}' ({org_id}). Type 'yes' to confirm: ")
                if confirm.lower() == 'yes':
                    disable_sast_for_org(org_id)
                else:
                    print(f"Skipped disabling SAST for {org_id}.")
            else:
                print(f"⚠️ Org ID {org_id} not found in the list of SAST-enabled orgs. Skipping.")


    # --- Step 3: Delete SAST Projects (Optional) ---
    print("\n--- 🗑️ STEP 3: DELETE SAST PROJECTS (OPTIONAL) ---")
    if input("Do you want to list and potentially delete SAST projects from any orgs? (y/n): ").lower() == 'y':
        org_ids_to_scan = input("Enter Org IDs to scan for SAST projects, separated by commas: ").strip()
        for org_id in [oid.strip() for oid in org_ids_to_scan.split(',')]:
            org_name = next((o['name'] for o in organizations if o['id'] == org_id), "Unknown")
            print(f"\nFetching SAST projects for '{org_name}' ({org_id})...")
            sast_projects = get_sast_projects(org_id)
            if not sast_projects:
                print(f"  No SAST projects found for Org ID {org_id}.")
                continue
            
            print(f"  Found {len(sast_projects)} SAST projects:")
            for proj in sast_projects:
                print(f"    - {proj['name']} (ID: {proj['id']})")
            
            if input(f"  Do you want to delete any of these {len(sast_projects)} projects? (y/n): ").lower() == 'y':
                project_ids_to_delete = input("  Enter Project IDs to delete, separated by commas: ").strip()
                for proj_id in [pid.strip() for pid in project_ids_to_delete.split(',')]:
                    proj_name = next((p['name'] for p in sast_projects if p['id'] == proj_id), "Unknown")
                    confirm = input(f"  🚨 DANGER: You are about to permanently delete project '{proj_name}' ({proj_id}). To confirm, type the project ID again: ")
                    if confirm == proj_id:
                        delete_sast_project(org_id, proj_id)
                    else:
                        print(f"  Confirmation failed. Skipping deletion of project {proj_id}.")

    # --- Step 4: Export report ---
    print("\n--- 📄 STEP 4: EXPORT REPORT (OPTIONAL) ---")
    if input("Do you want to save a final report of all organizations to a JSON file? (y/n): ").lower() == 'y':
        json_filename = get_json_filename()
        try:
            with open(json_filename, 'w') as f:
                json.dump(organizations, f, indent=4)
            print(f"✅ Report successfully saved to '{json_filename}'")
            if input("Do you want to convert this report to an Excel sheet? (y/n): ").lower() == 'y':
                excel_filename = json_filename.replace('.json', '.xlsx')
                pd.json_normalize(organizations).to_excel(excel_filename, index=False)
                print(f"✅ Excel report saved as '{excel_filename}'")
        except Exception as e:
            print(f"❌ An error occurred during file export: {e}")

if __name__ == "__main__":
    main()
