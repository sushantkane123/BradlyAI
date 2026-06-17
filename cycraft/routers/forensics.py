"""
FastAPI Router for AI Threat Hunter & Memory Forensics
"""

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/forensics", tags=["Forensics & Threat Hunting"])

# In-memory mock process trees for speed and recursive structural fidelity
FORENSIC_TREES = {
    "DEV-WIN-SRV09": {
        "rootProcess": {
            "name": "services.exe",
            "pid": 820,
            "user": "NT AUTHORITY\\SYSTEM",
            "reputation": "Trusted (OS)",
            "cpu": "0.1%",
            "memory": "14.2 MB",
            "children": [
                {
                    "name": "svchost.exe",
                    "pid": 1420,
                    "user": "NT AUTHORITY\\NETWORK SERVICE",
                    "reputation": "Trusted (OS)",
                    "cpu": "0.2%",
                    "memory": "22.1 MB",
                    "children": []
                },
                {
                    "name": "jenkins.exe",
                    "pid": 3912,
                    "user": "cycraft\\svc_jenkins",
                    "reputation": "Trusted (Verified)",
                    "cpu": "4.8%",
                    "memory": "410.5 MB",
                    "children": [
                        {
                            "name": "powershell.exe",
                            "pid": 6104,
                            "user": "cycraft\\svc_jenkins",
                            "reputation": "Malicious (CyCraft AI Flagged)",
                            "cpu": "12.4%",
                            "memory": "89.0 MB",
                            "highlight": True,
                            "details": "Executed with arguments: -nop -w hidden -EncodedCommand 'SABlAGwAbABvAFcAbwByAGwAZAA='",
                            "network": "Outbound TCP to 45.33.12.9:443",
                            "dlls": ["amsi.dll (Patched / Bypassed)", "kernel32.dll", "ws2_32.dll"],
                            "children": [
                                {
                                    "name": "rundll32.exe",
                                    "pid": 6188,
                                    "user": "cycraft\\svc_jenkins",
                                    "reputation": "Malicious (Injected Payload)",
                                    "cpu": "25.1%",
                                    "memory": "120.4 MB",
                                    "highlight": True,
                                    "details": "Reflective DLL Injection detected. Attempting to acquire a handle to lsass.exe (PID 692).",
                                    "network": "Listening on Port 13337",
                                    "dlls": ["ntdll.dll", "advapi32.dll"],
                                    "children": []
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    },
    "FIN-WRK-102": {
        "rootProcess": {
            "name": "explorer.exe",
            "pid": 2412,
            "user": "cycraft\\jsmith",
            "reputation": "Trusted",
            "cpu": "1.2%",
            "memory": "115.8 MB",
            "children": [
                {
                    "name": "winword.exe",
                    "pid": 4502,
                    "user": "cycraft\\jsmith",
                    "reputation": "Trusted",
                    "cpu": "0.5%",
                    "memory": "84.2 MB",
                    "children": [
                        {
                            "name": "cmd.exe",
                            "pid": 4890,
                            "user": "cycraft\\jsmith",
                            "reputation": "Suspicious",
                            "cpu": "0.0%",
                            "memory": "4.1 MB",
                            "highlight": True,
                            "details": "Spawned from Office application. Executing macro shellcode.",
                            "network": "None",
                            "dlls": [],
                            "children": []
                        }
                    ]
                }
            ]
        }
    }
}

@router.get("/process-tree/{hostname}")
def get_process_tree(hostname: str):
    """
    Retrieve live memory execution process tree for a monitored host
    """
    if hostname not in FORENSIC_TREES:
        raise HTTPException(status_code=404, detail=f"Process tree for host {hostname} not monitored.")
    return FORENSIC_TREES[hostname]

@router.post("/deep-scan/{hostname}")
def execute_memory_deep_scan(hostname: str):
    """
    Execute AI Copilot Memory Deep Scan on a target host
    """
    return {
        "status": "VERIFIED",
        "hostname": hostname,
        "report": f"CyCraft AI Deep Scan completed on {hostname}. Confirmed high-severity reflective DLL injection. Driverless containment successfully isolated network adapter."
    }
