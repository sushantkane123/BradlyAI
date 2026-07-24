"""BradlyAI - Real Detection Engine — rule-based detection on real logs"""
import re
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("bradlyai.detection")

@dataclass
class DetectionRule:
    id: str
    name: str
    severity: str
    mitre: str
    patterns: List[str]

@dataclass
class RealAlert:
    id: str
    severity: str
    title: str
    endpoint: str
    ip: str
    timestamp: str
    mitre: str
    status: str
    ai_confidence: str
    storyline: List[Dict]
    rule_id: str
    raw_event: Dict

class RealDetectionEngine:
    def __init__(self):
        self.rules = [
            DetectionRule("R001", "PowerShell Encoded Command", "CRITICAL", "T1059.001 - PowerShell",
                [r"powershell.*-enc", r"powershell.*-EncodedCommand", r"FromBase64String", r"IEX\s*\("]),
            DetectionRule("R002", "Suspicious SMB Lateral Movement", "HIGH", "T1210 - Exploitation of Remote Services",
                [r"smb.*445.*auth", r"anonymous.*logon", r"lateral.*movement"]),
            DetectionRule("R003", "Data Exfiltration Attempt", "HIGH", "T1048 - Exfiltration",
                [r"exfil|large.*transfer", r"\.zip.*upload", r"tor|onion|mega\.nz"]),
            DetectionRule("R004", "Cloud IAM Privilege Escalation", "HIGH", "T1078 - Valid Accounts",
                [r"AdministratorAccess", r"attach.*role", r"iam:PassRole"]),
            DetectionRule("R005", "Process Injection / Reflective DLL", "CRITICAL", "T1055 - Process Injection",
                [r"VirtualAllocEx|WriteProcessMemory", r"CreateRemoteThread", r"reflective.*dll"]),
            DetectionRule("R006", "Brute Force / Failed Logins", "MEDIUM", "T1110 - Brute Force",
                [r"failed.*login|authentication.*fail", r"invalid.*password"]),
        ]
        self.counter = 10000

    def detect(self, event: Dict[str, Any]) -> Optional[RealAlert]:
        message = (str(event.get("message", "")) + " " + str(event.get("raw", ""))).lower()
        source = event.get("source", event.get("host", "unknown-host"))
        ip = event.get("ip", event.get("src_ip", ""))
        now = datetime.now(timezone.utc)
        for rule in self.rules:
            for pattern in rule.patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    self.counter += 1
                    alert_id = f"ALT-{self.counter}"
                    logger.info(f"Rule {rule.id} matched → {alert_id}: {rule.name} on {source}")
                    return RealAlert(
                        id=alert_id, severity=rule.severity, title=rule.name, endpoint=source, ip=ip,
                        timestamp=now.strftime("%Y-%m-%d %H:%M:%S UTC"), mitre=rule.mitre,
                        status="Detected", ai_confidence="87%",
                        storyline=[
                            {"time": now.strftime("%H:%M:%S"), "event": f"Event received from {source}"},
                            {"time": now.strftime("%H:%M:%S"), "event": f"Matched rule {rule.id}: {rule.name}"},
                        ],
                        rule_id=rule.id, raw_event=event,
                    )
        return None

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def total_detections(self) -> int:
        return self.counter - 10000

detection_engine = RealDetectionEngine()
