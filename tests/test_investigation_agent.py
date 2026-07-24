"""End-to-end tests for the evidence-first SOC investigation agent."""
from fastapi.testclient import TestClient

from bradlyai.main import app
from bradlyai.database import SessionLocal
from bradlyai.services.bootstrap import run_all

# TestClient without a context manager does not trigger FastAPI lifespan in every
# supported Starlette version, so bootstrap the local admin deterministically.
run_all(SessionLocal())
client = TestClient(app)


def _admin_token() -> str:
    response = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "Admin123!ChangeMe",
    })
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_agent_investigates_a_real_ingested_event_without_containment():
    ingest = client.post("/api/v1/ingest/events", json={
        "source": "defender",
        "mode": "shadow",
        "payload": {
            "id": "agent-test-001",
            "alertTitle": "Suspicious PowerShell activity in test endpoint",
            "severity": "High",
            "deviceName": "TEST-AGENT-ENDPOINT",
            "sourceIp": "198.51.100.56",
            "processName": "powershell.exe -enc test",
            "mitreTechniques": "T1059.001",
        },
    })
    assert ingest.status_code == 200, ingest.text
    alert_id = ingest.json()["alert"]["id"]

    headers = {"Authorization": f"Bearer {_admin_token()}"}
    response = client.post(f"/api/v1/agent/alerts/{alert_id}/investigate", headers=headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["alert_id"] == alert_id
    assert result["recommendation"] == "ESCALATE"
    assert result["plan"]
    assert result["evidence"]
    assert result["hypotheses"]
    assert result["policy"]["requires_external_connector_evidence"] is True

    history = client.get(f"/api/v1/agent/alerts/{alert_id}/investigations", headers=headers)
    assert history.status_code == 200
    assert history.json()["count"] >= 1
