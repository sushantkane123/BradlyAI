"""
FastAPI Router for MITRE ATT&CK® Enterprise Tactical Matrix
"""

from fastapi import APIRouter

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])

MITRE_MATRIX_DATA = [
    {
        "tactic": "Initial Access",
        "techniques": [
            {"id": "T1566", "name": "Phishing", "active": True, "count": 2, "threat": "Critical"},
            {"id": "T1190", "name": "Exploit Public-Facing App", "active": True, "count": 1, "threat": "High"},
            {"id": "T1078", "name": "Valid Accounts", "active": True, "count": 2, "threat": "Medium"},
            {"id": "T1195", "name": "Supply Chain Compromise", "active": False, "count": 0, "threat": "None"}
        ]
    },
    {
        "tactic": "Execution",
        "techniques": [
            {"id": "T1059", "name": "Command & Scripting Interpreter", "active": True, "count": 4, "threat": "Critical"},
            {"id": "T1203", "name": "Exploitation for Client Execution", "active": False, "count": 0, "threat": "None"},
            {"id": "T1053", "name": "Scheduled Task/Job", "active": True, "count": 1, "threat": "Low"},
            {"id": "T1047", "name": "Windows Management Instrumentation", "active": False, "count": 0, "threat": "None"}
        ]
    },
    {
        "tactic": "Persistence",
        "techniques": [
            {"id": "T1543", "name": "Create or Modify System Process", "active": True, "count": 1, "threat": "High"},
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "active": False, "count": 0, "threat": "None"},
            {"id": "T1136", "name": "Create Account", "active": False, "count": 0, "threat": "None"},
            {"id": "T1574", "name": "Hijack Execution Flow", "active": False, "count": 0, "threat": "None"}
        ]
    },
    {
        "tactic": "Privilege Escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "active": True, "count": 2, "threat": "Critical"},
            {"id": "T1055", "name": "Process Injection", "active": True, "count": 3, "threat": "Critical"},
            {"id": "T1484", "name": "Domain Policy Modification", "active": False, "count": 0, "threat": "None"}
        ]
    },
    {
        "tactic": "Defense Evasion",
        "techniques": [
            {"id": "T1562", "name": "Impair Defenses", "active": True, "count": 2, "threat": "High"},
            {"id": "T1027", "name": "Obfuscated Files or Information", "active": True, "count": 3, "threat": "High"},
            {"id": "T1070", "name": "Indicator Removal", "active": False, "count": 0, "threat": "None"}
        ]
    },
    {
        "tactic": "Credential Access",
        "techniques": [
            {"id": "T1003", "name": "OS Credential Dumping (LSASS)", "active": True, "count": 3, "threat": "Critical"},
            {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "active": True, "count": 1, "threat": "High"},
            {"id": "T1110", "name": "Brute Force", "active": True, "count": 1, "threat": "Medium"}
        ]
    },
    {
        "tactic": "Lateral Movement",
        "techniques": [
            {"id": "T1210", "name": "Exploitation of Remote Services", "active": True, "count": 2, "threat": "Critical"},
            {"id": "T1021", "name": "Remote Services (SMB/RDP)", "active": True, "count": 2, "threat": "High"},
            {"id": "T1091", "name": "Replication Through Removable Media", "active": False, "count": 0, "threat": "None"}
        ]
    },
    {
        "tactic": "Exfiltration / C2",
        "techniques": [
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "active": True, "count": 1, "threat": "High"},
            {"id": "T1571", "name": "Non-Standard Port", "active": True, "count": 2, "threat": "Medium"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "active": True, "count": 1, "threat": "Low"}
        ]
    }
]

@router.get("/matrix")
def get_mitre_matrix():
    """
    Get interactive 14-tactic MITRE ATT&CK coverage matrix
    """
    return MITRE_MATRIX_DATA

@router.get("/technique/{technique_id}")
def get_technique_guide(technique_id: str):
    """
    Get defensive multi-model guide for a specific technique
    """
    return {
        "technique_id": technique_id,
        "guide": f"CyCraft utilizes active behavioral kernel scanners and multi-model ML hooks to autonomously detect, contain, and neutralise {technique_id} without human intervention."
    }
