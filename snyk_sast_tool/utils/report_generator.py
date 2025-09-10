import json
import pandas as pd
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime

class ReportGenerator:
    @staticmethod
    def generate_filename(prefix: str, extension: str = "json") -> str:
        """Generate a filename with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.{extension}"
    
    @staticmethod
    def save_json(data: Any, filepath: str) -> str:
        """Save data to a JSON file"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return filepath
    
    @staticmethod
    def save_excel(data: List[Dict], filepath: str) -> str:
        """Save data to an Excel file"""
        df = pd.DataFrame(data)
        df.to_excel(filepath, index=False, engine='openpyxl')
        return filepath
    
    @staticmethod
    def prepare_audit_report(audit_results: Dict) -> Dict:
        """Prepare audit results for reporting"""
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_orgs": len(audit_results["sast_enabled_orgs"]) + len(audit_results["sast_disabled_orgs"]),
                "sast_enabled_count": len(audit_results["sast_enabled_orgs"]),
                "sast_disabled_count": len(audit_results["sast_disabled_orgs"])
            },
            "organizations": []
        }
        
        for org in audit_results["sast_enabled_orgs"]:
            org_data = {
                "id": org["id"],
                "name": org["name"],
                "sast_enabled": True,
                "sast_projects": org.get("sast_projects", [])
            }
            report["organizations"].append(org_data)
        
        for org in audit_results["sast_disabled_orgs"]:
            org_data = {
                "id": org["id"],
                "name": org["name"],
                "sast_enabled": False,
                "sast_projects": []
            }
            report["organizations"].append(org_data)
            
        return report
    
    @staticmethod
    def prepare_flat_report(audit_results: Dict) -> List[Dict]:
        """Prepare a flat report for Excel export"""
        flat_data = []
        
        for org in audit_results["sast_enabled_orgs"]:
            if org.get("sast_projects"):
                for project in org["sast_projects"]:
                    flat_data.append({
                        "org_name": org["name"],
                        "org_id": org["id"],
                        "sast_status": "Enabled",
                        "project_name": project.get("name"),
                        "project_id": project.get("id"),
                        "project_created": project.get("created")
                    })
            else:
                flat_data.append({
                    "org_name": org["name"],
                    "org_id": org["id"],
                    "sast_status": "Enabled",
                    "project_name": "No SAST Projects",
                    "project_id": None,
                    "project_created": None
                })
                
        for org in audit_results["sast_disabled_orgs"]:
            flat_data.append({
                "org_name": org["name"],
                "org_id": org["id"],
                "sast_status": "Disabled",
                "project_name": None,
                "project_id": None,
                "project_created": None
            })
            
        return flat_data
