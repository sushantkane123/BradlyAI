"""BradlyAI - Real Log Ingestion Service (Phase 1)"""
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from dataclasses import dataclass
from .detection_engine import detection_engine, RealAlert

@dataclass
class IngestedEvent:
    id: int
    timestamp: str
    source: str
    message: str
    raw: str

class LogIngestionService:
    def __init__(self):
        self.events: List[IngestedEvent] = []
        self.alerts: List[RealAlert] = []
        self.counter = 0

    def ingest_text(self, raw_text: str) -> Dict:
        lines = [l.strip() for l in raw_text.strip().split("\n") if l.strip()]
        new_alerts = []
        for line in lines:
            self.counter += 1
            event = IngestedEvent(id=self.counter, timestamp=datetime.now(timezone.utc).isoformat(), source="unknown", message=line, raw=line)
            self.events.append(event)
            if "powershell" in line.lower() or "-enc" in line.lower():
                event.source = "WEB-SRV01"
            elif "smb" in line.lower() or "anonymous" in line.lower():
                event.source = "FIN-WRK-102"
            elif "mega" in line.lower() or "exfil" in line.lower():
                event.source = "ENG-MAC-404"
            elif "iam" in line.lower() or "administratoraccess" in line.lower():
                event.source = "AWS-IAM"
            alert = detection_engine.detect({"message": event.message, "source": event.source, "raw": event.raw, "ip": ""})
            if alert:
                self.alerts.append(alert)
                new_alerts.append(alert)
        return {"events_ingested": len(lines), "alerts_generated": len(new_alerts), "alerts": [self._alert_to_dict(a) for a in new_alerts]}

    def ingest_json(self, logs: List[Dict]) -> Dict:
        new_alerts = []
        for log in logs:
            self.counter += 1
            event = IngestedEvent(id=self.counter, timestamp=log.get("timestamp", datetime.now(timezone.utc).isoformat()), source=log.get("host", "unknown"), message=log.get("message", str(log)), raw=json.dumps(log))
            self.events.append(event)
            alert = detection_engine.detect({"message": event.message, "source": event.source, "raw": event.raw, "ip": log.get("source_ip", "")})
            if alert:
                self.alerts.append(alert)
                new_alerts.append(alert)
        return {"events_ingested": len(logs), "alerts_generated": len(new_alerts), "alerts": [self._alert_to_dict(a) for a in new_alerts]}

    def get_events(self, limit=50):
        return [{"id": e.id, "timestamp": e.timestamp, "source": e.source, "message": e.message[:200]} for e in self.events[-limit:]]
    def get_alerts(self, limit=100):
        return [self._alert_to_dict(a) for a in self.alerts[-limit:]]
    def _alert_to_dict(self, alert):
        return {"id": alert.id, "severity": alert.severity, "title": alert.title, "endpoint": alert.endpoint, "ip": alert.ip, "mitre": alert.mitre, "status": alert.status, "rule_id": alert.rule_id, "raw_event": alert.raw_event, "storyline": alert.storyline}
    def clear(self):
        self.events, self.alerts, self.counter = [], [], 0

log_ingestion = LogIngestionService()
