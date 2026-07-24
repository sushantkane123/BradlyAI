"""Contract tests for real SIEM/XDR/EDR ingestion in safe shadow mode."""
from fastapi.testclient import TestClient

from bradlyai.main import app

client = TestClient(app)


def sentinel_payload() -> dict:
    return {
        "SystemAlertId": "test-sentinel-001",
        "AlertDisplayName": "Suspicious PowerShell command",
        "Description": "Sanitized test event",
        "Severity": "High",
        "CompromisedEntity": "TEST-WIN-01",
        "StartTimeUtc": "2026-07-24T12:00:00Z",
        "Entities": [{"Type": "ip", "Address": "198.51.100.10"}],
        "Techniques": "T1059.001",
    }


def test_supported_real_event_sources_are_advertised():
    response = client.get("/api/v1/ingest/sources")
    assert response.status_code == 200
    sources = response.json()["sources"]
    for source in ("wazuh", "splunk", "sentinel", "defender", "crowdstrike", "elastic", "siem", "xdr", "edr"):
        assert source in sources


def test_sentinel_event_is_persisted_and_audited_in_shadow_mode():
    response = client.post("/api/v1/ingest/events", json={
        "source": "sentinel",
        "mode": "shadow",
        "payload": sentinel_payload(),
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["stored"] is True
    assert body["source"] == "sentinel"
    assert body["mode"] == "shadow"
    assert body["alert"]["id"].startswith("SEN-")
    assert body["alert"]["severity"] == "HIGH"
    assert body["action"]["action_taken"] in ("shadow_no_action", "escalated")

    detail = client.get(f"/api/v1/alerts/{body['alert']['id']}")
    assert detail.status_code == 200
    stored = detail.json()
    assert stored["source"] == "sentinel"
    assert "test-sentinel-001" in stored["raw_event"]


def test_edr_xdr_and_crowdstrike_batch_replay():
    response = client.post("/api/v1/ingest/events/batch", json={
        "mode": "shadow",
        "events": [
            {"source": "edr", "payload": {"alert_id": "test-edr-001", "message": "Lab EDR event", "risk_score": 88, "endpoint": "TEST-EDR-01", "ip": "198.51.100.11"}},
            {"source": "xdr", "payload": {"event_id": "test-xdr-001", "name": "Lab XDR event", "severity": "high", "host": "TEST-XDR-01", "src_ip": "198.51.100.12"}},
            {"source": "crowdstrike", "payload": {"resources": [{"detection_id": "test-cs-001", "max_severity_displayname": "High", "device": {"hostname": "TEST-CS-01", "local_ip": "198.51.100.13"}, "behaviors": [{"description": "Lab Falcon behavior", "severity": 80, "filename": "test.exe"}]}]}},
        ],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 3
    assert body["stored"] == 3
    assert body["failed"] == 0
    assert {item["source"] for item in body["results"]} == {"edr", "xdr", "crowdstrike"}


def test_unknown_source_is_rejected():
    response = client.post("/api/v1/ingest/events", json={"source": "unsupported-vendor", "payload": {"id": "x"}})
    assert response.status_code == 400
