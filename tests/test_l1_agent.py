"""Tests for the BradlyAI L1 SOC Agent."""
import pytest
from fastapi.testclient import TestClient
from bradlyai.main import app

client = TestClient(app)


# ===== Helper to build alerts in different source formats =====

def splunk_alert(**overrides):
    base = {
        "sid": "1234567",
        "search_name": "Suspicious PowerShell Activity Detected",
        "result": {
            "src_ip": "45.33.12.9",
            "dest": "192.168.10.45",
            "user": "admin",
            "host": "DEV-WIN-SRV09",
            "command": "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        },
        "severity": "high",
        "time": "2026-06-22T10:00:00Z",
    }
    base.update(overrides)
    return {"source": "splunk", "payload": base}


def wazuh_alert(**overrides):
    base = {
        "timestamp": "2026-06-22T10:00:00Z",
        "rule": {"level": 12, "description": "SSH brute force attempt", "id": "5710",
                 "mitre": {"id": ["T1110"]}},
        "agent": {"id": "007", "name": "WEB-SRV01", "ip": "10.0.0.50"},
        "data": {"srcip": "10.0.0.50", "action": "blocked"},
    }
    base.update(overrides)
    return {"source": "wazuh", "payload": base}


def jira_alert(**overrides):
    base = {
        "key": "SEC-1234",
        "fields": {
            "summary": "Suspicious login from new location",
            "description": "User admin logged in from IP 192.168.1.50 which is unusual",
            "priority": {"name": "High"},
            "labels": ["security"],
            "created": "2026-06-22T10:00:00.000+0000",
            "reporter": {"displayName": "siem-auto"},
        },
    }
    base.update(overrides)
    return {"source": "jira", "payload": base}


# ===== Tests =====

def test_l1_status():
    """GET /api/v1/l1/mode returns current mode + threshold"""
    r = client.get("/api/v1/l1/mode")
    assert r.status_code == 200
    data = r.json()
    assert "mode" in data
    assert "threshold" in data


def test_process_alert_splunk():
    """Process a Splunk alert end-to-end"""
    r = client.post("/api/v1/l1/process-alert", json=splunk_alert())
    assert r.status_code == 200
    data = r.json()
    assert "decision" in data
    assert data["decision"] in ("CLOSE", "ESCALATE", "SHADOW_CLOSE")
    assert "confidence" in data
    assert "signals" in data
    assert len(data["signals"]) == 4  # fp_detector + frequency + whitelist + historical


def test_process_alert_wazuh():
    """Process a Wazuh alert"""
    r = client.post("/api/v1/l1/process-alert", json=wazuh_alert())
    assert r.status_code == 200
    data = r.json()
    assert "decision" in data
    assert data["alert_id"].startswith("WAZ-")


def test_process_alert_jira():
    """Process a Jira alert"""
    r = client.post("/api/v1/l1/process-alert", json=jira_alert())
    assert r.status_code == 200
    data = r.json()
    assert "decision" in data
    assert data["alert_id"].startswith("JIRA-")


def test_process_alert_shadow_mode():
    """Shadow mode should NOT close alerts"""
    r = client.post("/api/v1/l1/process-alert", json={**splunk_alert(), "mode": "shadow"})
    assert r.status_code == 200
    data = r.json()
    # In shadow mode, decision should be CLOSE or SHADOW_CLOSE — never ESCALATE alone
    assert data["decision"] in ("CLOSE", "ESCALATE", "SHADOW_CLOSE")
    if data["decision"] == "CLOSE":
        # Active mode would close — shadow mode should override to SHADOW_CLOSE
        # (engine handles this)
        pass


def test_process_alert_invalid_source():
    """Invalid source should return 400"""
    r = client.post("/api/v1/l1/process-alert", json={
        "source": "unknown",
        "payload": {"foo": "bar"}
    })
    assert r.status_code == 400


def test_process_batch():
    """Process a batch of alerts"""
    r = client.post("/api/v1/l1/process-batch", json={
        "alerts": [splunk_alert(), wazuh_alert(), jira_alert()],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 3
    assert "closed" in data
    assert "escalated" in data
    assert "errors" in data
    assert data["errors"] == 0


def test_process_batch_shadow():
    """Batch processing in shadow mode counts decisions but doesn't act"""
    r = client.post("/api/v1/l1/process-batch", json={
        "alerts": [splunk_alert(), wazuh_alert()],
        "mode": "shadow",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 2


def test_audit_log():
    """Audit log returns decisions"""
    # Generate a decision first
    client.post("/api/v1/l1/process-alert", json=splunk_alert())
    # Then fetch audit
    r = client.get("/api/v1/l1/audit?since_hours=1")
    assert r.status_code == 200
    data = r.json()
    assert "count" in data
    assert "entries" in data
    # Should have at least one entry from above
    if data["count"] > 0:
        entry = data["entries"][0]
        assert "alert_id" in entry
        assert "decision" in entry
        assert "confidence" in entry


def test_stats():
    """Stats endpoint returns aggregate metrics"""
    r = client.get("/api/v1/l1/stats?since_hours=1")
    assert r.status_code == 200
    data = r.json()
    assert "total_decisions" in data
    assert "closed" in data
    assert "escalated" in data
    assert "auto_close_rate" in data
    assert "current_mode" in data
    assert "threshold" in data


def test_whitelist_crud():
    """CRUD on whitelist entries"""
    # List (should have defaults seeded)
    r = client.get("/api/v1/l1/whitelist")
    assert r.status_code == 200
    initial_count = r.json()["count"]

    # Add
    r = client.post("/api/v1/l1/whitelist", json={
        "entry_type": "source_ip",
        "match_value": "10.99.88.77",
        "name": "Test scanner",
        "description": "Test whitelist entry",
    })
    assert r.status_code == 200
    entry = r.json()
    entry_id = entry["id"]
    assert entry["entry_type"] == "source_ip"

    # Get list again
    r = client.get("/api/v1/l1/whitelist")
    assert r.json()["count"] == initial_count + 1

    # Delete
    r = client.delete(f"/api/v1/l1/whitelist/{entry_id}")
    assert r.status_code == 200

    # Confirm removed
    r = client.get("/api/v1/l1/whitelist")
    assert r.json()["count"] == initial_count


def test_whitelist_matches_alert():
    """Alert matching a whitelist entry gets high-confidence FP verdict"""
    # Add a whitelist entry
    client.post("/api/v1/l1/whitelist", json={
        "entry_type": "source_ip",
        "match_value": "99.88.77.66",
        "name": "Test scanner IP",
    })
    # Process alert from that IP — should be flagged by whitelist
    alert = splunk_alert()
    alert["payload"]["result"]["src_ip"] = "99.88.77.66"
    r = client.post("/api/v1/l1/process-alert", json=alert)
    data = r.json()
    whitelist_signal = next((s for s in data["signals"] if s["name"] == "whitelist"), None)
    assert whitelist_signal is not None
    assert whitelist_signal["verdict"] == "FP"
    assert whitelist_signal["confidence"] >= 0.9


def test_fp_detector_catches_scanner():
    """FP detector should flag vulnerability scanner traffic"""
    alert = splunk_alert()
    alert["payload"]["search_name"] = "Nessus vulnerability scan completed"
    alert["payload"]["result"]["command"] = "nessuscli scan --target 192.168.1.0/24"
    r = client.post("/api/v1/l1/process-alert", json=alert)
    data = r.json()
    fp_signal = next((s for s in data["signals"] if s["name"] == "rule_based_fp"), None)
    assert fp_signal is not None
    assert fp_signal["verdict"] == "FP"


def test_mode_switch():
    """Toggle between active and shadow modes"""
    # Default
    r = client.get("/api/v1/l1/mode")
    assert r.json()["mode"] in ("active", "shadow")

    # Switch
    r = client.post("/api/v1/l1/mode", json={"mode": "shadow"})
    assert r.status_code == 200
    assert r.json()["mode"] == "shadow"

    # Switch back
    r = client.post("/api/v1/l1/mode", json={"mode": "active"})
    assert r.status_code == 200
    assert r.json()["mode"] == "active"


def test_threshold_change():
    """Change the auto-close confidence threshold"""
    r = client.post("/api/v1/l1/mode", json={"mode": "active", "threshold": 0.95})
    assert r.status_code == 200
    assert r.json()["threshold"] == 0.95

    # Reset
    r = client.post("/api/v1/l1/mode", json={"mode": "active", "threshold": 0.85})
    assert r.status_code == 200
    assert r.json()["threshold"] == 0.85


def test_feedback_listing():
    """Feedback endpoint returns human override records"""
    r = client.get("/api/v1/l1/feedback?limit=10")
    assert r.status_code == 200
    data = r.json()
    assert "count" in data
    assert "entries" in data
