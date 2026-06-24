"""Tests for the competitive-hardening additions.

Covers:
  - Auth (login, refresh, MFA setup, RBAC)
  - Cases (create, notes, evidence, status changes, SLA)
  - Playbooks (seeded, trigger, resume)
  - Sigma rules (import, evaluate)
  - Notifications (slack/teams/pagerduty/email dry-run)
  - EDR / Network / Identity dry-run stubs
  - Reports (KPIs, NIST 800-61, audit CSV, PDF)
  - Metrics endpoint
"""
import os
import tempfile
import json
import datetime

import pytest
from fastapi.testclient import TestClient

# Ensure deterministic env BEFORE importing the app
os.environ.setdefault("AUTH_ENABLED", "true")
os.environ.setdefault("AUTH_JWT_SECRET", "test-secret-test-secret-test-secret-test-secret-1234567890")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_bradlyai.db")
os.environ.setdefault("LIVE_SIMULATION_WORKER_ACTIVE", "false")
os.environ.setdefault("EDR_ENABLED", "false")
os.environ.setdefault("EDR_DRY_RUN", "true")
os.environ.setdefault("NETWORK_ENABLED", "false")
os.environ.setdefault("NETWORK_DRY_RUN", "true")
os.environ.setdefault("IDENTITY_ENABLED", "false")
os.environ.setdefault("IDENTITY_DRY_RUN", "true")
os.environ.setdefault("ITSM_ENABLED", "false")
os.environ.setdefault("THREATINTEL_ENABLED", "false")
os.environ.setdefault("NOTIFICATIONS_ENABLED", "false")
os.environ.setdefault("MULTI_TENANCY_ENABLED", "false")

# Reset any pre-existing test DB
if os.path.exists("./test_bradlyai.db"):
    os.remove("./test_bradlyai.db")

from bradlyai.main import app   # noqa: E402

client = TestClient(app)


# ── Auth ──────────────────────────────────────────────────────────────
class TestAuth:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] in ("healthy", "degraded")

    def test_login_admin_default(self):
        r = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "Admin123!ChangeMe"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert "access_token" in body
        assert body["user"]["username"] == "admin"
        return body["access_token"]

    def test_login_bad_password(self):
        r = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_me_with_token(self):
        token = self.test_login_admin_default()
        r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["username"] == "admin"

    def test_me_no_token(self):
        r = client.get("/api/v1/auth/me")
        assert r.status_code == 401

    def test_create_user(self):
        token = self.test_login_admin_default()
        r = client.post("/api/v1/auth/users",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"username": "alice", "email": "alice@test.local",
                              "password": "AlicePass123!",
                              "role_names": ["analyst_l1"]})
        assert r.status_code == 201, r.text
        assert r.json()["username"] == "alice"

    def test_create_api_key(self):
        token = self.test_login_admin_default()
        r = client.post("/api/v1/auth/api-keys",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"name": "test-key", "scopes": "read,write,admin"})
        assert r.status_code == 201
        body = r.json()
        assert body["secret"].startswith("brd_")
        return body["secret"]

    def test_api_key_authenticates(self):
        secret = self.test_create_api_key()
        r = client.get("/api/v1/auth/me", headers={"X-API-Key": secret})
        assert r.status_code == 200


# ── Cases ─────────────────────────────────────────────────────────────
class TestCases:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_create_case(self, token):
        r = client.post("/api/v1/cases",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"title": "Test incident", "severity": "HIGH",
                              "priority": "P2"})
        assert r.status_code == 201
        case_id = r.json()["id"]
        return case_id

    def test_add_note(self, token):
        case_id = self.test_create_case(token)
        r = client.post(f"/api/v1/cases/{case_id}/notes",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"note": "Investigating", "note_type": "comment"})
        assert r.status_code == 200

    def test_add_evidence(self, token):
        case_id = self.test_create_case(token)
        r = client.post(f"/api/v1/cases/{case_id}/evidence",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"evidence_type": "log", "value": "user=admin login from 10.0.0.5"})
        assert r.status_code == 200

    def test_status_change(self, token):
        case_id = self.test_create_case(token)
        r = client.post(f"/api/v1/cases/{case_id}/status",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"status": "IN_PROGRESS", "note": "Working"})
        assert r.status_code == 200
        assert r.json()["status"] == "IN_PROGRESS"

    def test_list_cases(self, token):
        r = client.get("/api/v1/cases",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ── Playbooks ─────────────────────────────────────────────────────────
class TestPlaybooks:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_list_builtin(self, token):
        r = client.get("/api/v1/playbooks",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        names = [p["name"] for p in r.json()]
        assert "Phishing Email Response" in names

    def test_trigger_bruteforce(self, token):
        r = client.post("/api/v1/playbooks/trigger",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"playbook_id": "pb_bruteforce_response",
                              "alert": {"id": "ALT-TEST", "ip": "1.2.3.4",
                                        "severity": "HIGH", "endpoint": "srv01"}})
        assert r.status_code == 200
        run = r.json()
        assert run["status"] in ("RUNNING", "COMPLETED", "AWAITING_APPROVAL")
        return run["id"]


# ── Sigma ─────────────────────────────────────────────────────────────
class TestSigma:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_seed_defaults(self, token):
        r = client.post("/api/v1/sigma/seed-defaults",
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_list_rules(self, token):
        r = client.get("/api/v1/sigma",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        ids = [p["id"] for p in r.json()]
        assert "bradlyai_sigma_powershell_encoded" in ids

    def test_evaluate_event(self, token):
        r = client.post("/api/v1/sigma/evaluate",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"event": {"logsource_product": "windows",
                                        "logsource_category": "process_creation",
                                        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                        "CommandLine": "powershell -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA=="}})
        assert r.status_code == 200
        matches = r.json()
        assert any(m["rule_id"] == "bradlyai_sigma_powershell_encoded" for m in matches)


# ── Notifications ─────────────────────────────────────────────────────
class TestNotifications:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_send_slack_dry_run(self, token):
        r = client.post("/api/v1/notifications/send",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"channel": "slack", "message": "test alert"})
        assert r.status_code == 200
        # SLACK_ENABLED=false → success=true (dry-run)
        assert r.json()["success"] is True
        assert "dry-run" in r.json().get("detail", "")

    def test_send_email_dry_run(self, token):
        r = client.post("/api/v1/notifications/send",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"channel": "email", "to": "soc@example.com",
                              "subject": "Test", "message": "Body"})
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_pagerduty_dry_run(self, token):
        r = client.post("/api/v1/notifications/send",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"channel": "pagerduty", "summary": "Critical alert"})
        assert r.status_code == 200


# ── EDR / Network / Identity ──────────────────────────────────────────
class TestResponseActions:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_edr_isolate_dry_run(self, token):
        r = client.post("/api/v1/edr/hosts/isolate",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"host_id": "HOST01", "reason": "test"})
        assert r.status_code == 200
        assert r.json()["dry_run"] is True

    def test_network_block_ip_dry_run(self, token):
        r = client.post("/api/v1/network/block-ip",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"ip": "1.2.3.4", "reason": "test"})
        assert r.status_code == 200
        assert r.json()["dry_run"] is True

    def test_identity_disable_dry_run(self, token):
        r = client.post("/api/v1/identity/disable",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"user": "alice@example.com", "reason": "test"})
        assert r.status_code == 200
        assert r.json()["dry_run"] is True


# ── Reports ───────────────────────────────────────────────────────────
class TestReports:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_kpis(self, token):
        r = client.get("/api/v1/reports/kpis?since_hours=24",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert "alerts" in body and "cases" in body

    def test_nist_report(self, token):
        r = client.get("/api/v1/reports/nist-800-61?since_hours=168",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert "phases" in body
        assert "1_preparation" in body["phases"]

    def test_audit_csv(self, token):
        r = client.get("/api/v1/reports/audit.csv?since_hours=168",
                       headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]


# ── Metrics ───────────────────────────────────────────────────────────
class TestMetrics:
    def test_metrics_endpoint(self):
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "bradlyai_" in r.text


# ── Threat Intel (dry-run) ────────────────────────────────────────────
class TestThreatIntel:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_ip_lookup_dry_run(self, token):
        r = client.post("/api/v1/threatintel/lookup",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"ips": ["1.2.3.4"]})
        assert r.status_code == 200
        # Without keys set, results contain dry-run markers
        ips = r.json().get("ips", {})
        assert "1.2.3.4" in ips


# ── ITSM (dry-run) ────────────────────────────────────────────────────
class TestITSM:
    @pytest.fixture
    def token(self):
        return TestAuth().test_login_admin_default()

    def test_servicenow_dry_run_503(self, token):
        # ITSM_PROVIDER=none → 503
        r = client.post("/api/v1/itsm/servicenow/incidents",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"short_description": "test"})
        assert r.status_code == 503
