import requests
import json
import os
import pandas as pd
from datetime import datetime

# --- Configuration ---
# Snyk API token is fetched from environment variables for security
SNYK_TOKEN = os.getenv("SNYK_TOKEN")
# Snyk API v1 and REST API base URLs
API_V1_BASE_URL = "https://api.snyk.io/v1"
API_REST_BASE_URL = "https://api.snyk.io/rest"
API_VERSION = "2024-05-24" # Recommended REST API version

# --- API Headers ---
HEADERS_V1 = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/json"
}
HEADERS_REST = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Accept": "application/vnd.api+json"
}

def get_json_filename():
    """Asks the user for a JSON filename, providing a default."""
    today_date = datetime.now().strftime("%Y-%m-%d")
    default_name = f"snyk_sast_audit_{today_date}.json"
    filename = input(f"Enter the JSON filename (default: {default_name}): ").strip()
    return filename if filename else default_name

def get_all_orgs_in_group(group_id):
    """Fetches all organizations for a given Snyk Group ID."""
    url = f"{API_V1_BASE_URL}/group/{group_id}/orgs"
    print(f"Fetching organizations for Group ID: {group_id}...")
    try:
        response = requests.post(url, headers=HEADERS_V1)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
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
    except requests.exceptions.RequestException:
        # A 404 might mean settings are not configured, which we treat as disabled.
        return {"sast_enabled": False}

def get_sast_projects(org_id):
    """Fetches all SAST projects for a given organization."""
    sast_projects = []
    url = f"{API_REST_BASE_URL}/orgs/{org_id}/projects?version={API_VERSION}&limit=100"
    print(f"  -> Checking for SAST projects in Org ID: {org_id}")
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
                        "name": project.get("attributes", {}).get("name"),
                        "created": project.get("attributes", {}).get("created")
                    })
            # Handle pagination
            url = data.get("links", {}).get("next", None)
    except requests.exceptions.RequestException as e:
        print(f"  -> ❌ Could not fetch projects for Org ID {org_id}: {e}")
    return sast_projects

def main():
    """Main function to run the audit script."""
    if not SNYK_TOKEN:
        print("❌ Error: SNYK_TOKEN environment variable not set.")
        return

    print("--- Snyk SAST Audit Tool ---")
    group_id = input("Enter your Snyk Group ID: ").strip()
    if not group_id:
        print("❌ Group ID is required.")
        return

    organizations = get_all_orgs_in_group(group_id)
    if not organizations:
        return

    audit_results = {
        "group_id": group_id,
        "sast_enabled_orgs": [],
        "sast_disabled_orgs": []
    }

    print("\n🔍 Auditing organization SAST settings and projects...")
    for org in organizations:
        org_id = org['id']
        org_name = org['name']
        settings = get_sast_settings(org_id)
        
        org_data = {
            "name": org_name,
            "id": org_id,
        }

        if settings.get("sast_enabled"):
            print(f"🟢 SAST is ENABLED for '{org_name}' ({org_id})")
            org_data["sast_projects"] = get_sast_projects(org_id)
            audit_results["sast_enabled_orgs"].append(org_data)
        else:
            print(f"⚪ SAST is DISABLED for '{org_name}' ({org_id})")
            audit_results["sast_disabled_orgs"].append(org_data)

    print("\n--- Audit Summary ---")
    print(f"Total Organizations Audited: {len(organizations)}")
    print(f"Orgs with SAST Enabled: {len(audit_results['sast_enabled_orgs'])}")
    print(f"Orgs with SAST Disabled: {len(audit_results['sast_disabled_orgs'])}")
    print("-----------------------\n")

    # --- Exporting Results ---
    if input("Do you want to export the full results to a JSON file? (y/n): ").lower() == 'y':
        json_filename = get_json_filename()
        try:
            with open(json_filename, 'w') as f:
                json.dump(audit_results, f, indent=4)
            print(f"✅ Results successfully saved to '{json_filename}'")

            if input("Do you want to convert the JSON output to an Excel file? (y/n): ").lower() == 'y':
                excel_filename = json_filename.replace('.json', '.xlsx')
                
                # Flatten the data for Excel
                flat_data = []
                for org in audit_results["sast_enabled_orgs"]:
                    if org.get("sast_projects"):
                        for project in org["sast_projects"]:
                            flat_data.append({
                                "org_name": org["name"],
                                "org_id": org["id"],
                                "sast_status": "Enabled",
                                "project_name": project["name"],
                                "project_id": project["id"]
                            })
                    else:
                         flat_data.append({
                            "org_name": org["name"],
                            "org_id": org["id"],
                            "sast_status": "Enabled",
                            "project_name": "No SAST Projects Found",
                            "project_id": None
                        })
                for org in audit_results["sast_disabled_orgs"]:
                     flat_data.append({
                        "org_name": org["name"],
                        "org_id": org["id"],
                        "sast_status": "Disabled",
                        "project_name": None,
                        "project_id": None
                    })

                df = pd.DataFrame(flat_data)
                df.to_excel(excel_filename, index=False, engine='openpyxl')
                print(f"✅ Excel file saved as '{excel_filename}'")

        except Exception as e:
            print(f"❌ An error occurred during file export: {e}")

if __name__ == "__main__":
    main()
