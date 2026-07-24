"""Tests for the Dropzone-style autonomous SOC investigation agent."""

import pytest
from bradlyai.database import SessionLocal, Base, engine
from bradlyai.models.alert import AlertModel

# Ensure tables exist
Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="module")
def db_module():
    """Module-scoped DB session."""
    db = SessionLocal()
    yield db
    db.rollback()
    db.close()


@pytest.fixture(scope="module")
def test_alert_ids():
    """Unique test alert IDs to avoid conflicts with seed data."""
    return [f"DZ-TEST-{i:03d}" for i in range(1, 5)]


@pytest.fixture(scope="module")
def sample_alerts(db_module, test_alert_ids):
    """Seed test alerts of different types. Module-scoped to avoid re-inserts."""
    existing = db_module.query(AlertModel).filter(
        AlertModel.id.in_(test_alert_ids)
    ).count()
    if existing > 0:
        # Already seeded
        return [db_module.query(AlertModel).filter(AlertModel.id == aid).first()
                for aid in test_alert_ids]

    alerts = [
        AlertModel(
            id=test_alert_ids[0],
            title="Suspicious PowerShell encoded command detected",
            severity="HIGH",
            source="sentinel",
            endpoint="WIN-SRV-01",
            ip="10.0.0.45",
            mitre="T1059.001 - PowerShell",
            raw_event='{"command": "powershell -enc ..."}',
            signature="sentinel:powershell-encoded",
            status="NEW",
            tenant_id="default",
        ),
        AlertModel(
            id=test_alert_ids[1],
            title="Nessus vulnerability scan detected",
            severity="LOW",
            source="wazuh",
            endpoint="SCANNER-01",
            ip="10.0.0.50",
            mitre="T1595 - Active Scanning",
            raw_event='{"rule": "1001", "description": "Vulnerability scanner heartbeat"}',
            signature="wazuh:scanner",
            status="NEW",
            tenant_id="default",
        ),
        AlertModel(
            id=test_alert_ids[2],
            title="Multiple failed login attempts from external IP",
            severity="MEDIUM",
            source="splunk",
            endpoint="DC-01",
            ip="45.33.12.9",
            mitre="T1110 - Brute Force",
            raw_event='{"user": "admin", "failed_count": 50}',
            signature="splunk:brute-force",
            status="NEW",
            tenant_id="default",
        ),
        AlertModel(
            id=test_alert_ids[3],
            title="Phishing email reported by user",
            severity="HIGH",
            source="defender",
            endpoint="WIN-WRK-05",
            ip="192.168.1.50",
            mitre="T1566 - Phishing",
            raw_event='{"email_from": "spoofed@evil.com", "attachment": "invoice.exe"}',
            signature="defender:phishing",
            status="NEW",
            tenant_id="default",
        ),
    ]
    for alert in alerts:
        db_module.add(alert)
    db_module.commit()
    for alert in alerts:
        db_module.refresh(alert)
    return alerts


class TestDropzoneAgent:
    """Test the Dropzone Autonomous Agent core functionality."""

    def test_classify_alert_type_malware(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[0])
        assert alert_type == "malware", f"Expected malware, got {alert_type}"

    def test_classify_alert_type_scanner(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[1])
        assert alert_type == "scanner", f"Expected scanner, got {alert_type}"

    def test_classify_alert_type_brute_force(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[2])
        assert alert_type == "brute_force", f"Expected brute_force, got {alert_type}"

    def test_classify_alert_type_phishing(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[3])
        assert alert_type == "phishing", f"Expected phishing, got {alert_type}"

    def test_extract_entities(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        entities = dropzone_agent._extract_entities(sample_alerts[0])
        assert len(entities["hosts"]) > 0
        assert len(entities["ips"]) > 0

    def test_phase_obtain(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[0])
        entities = dropzone_agent._extract_entities(sample_alerts[0])
        steps = dropzone_agent._phase_obtain(sample_alerts[0], alert_type, entities)
        assert len(steps) == 4
        for step in steps:
            assert step.status == "completed"
            assert step.phase == "OBTAIN"

    def test_phase_strategize(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[0])
        entities = dropzone_agent._extract_entities(sample_alerts[0])
        steps, hypotheses = dropzone_agent._phase_strategize(
            sample_alerts[0], alert_type, entities
        )
        assert len(steps) == 4
        assert len(hypotheses) >= 3
        assert hypotheses[0].likelihood == "high"

    def test_phase_analyze(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[0])
        entities = dropzone_agent._extract_entities(sample_alerts[0])
        _, hypotheses = dropzone_agent._phase_strategize(
            sample_alerts[0], alert_type, entities
        )
        mock_collect = []
        steps, final_hyps = dropzone_agent._phase_analyze(
            sample_alerts[0], alert_type, entities, hypotheses, mock_collect
        )
        assert len(steps) > 0
        assert len(final_hyps) >= 3
        for step in steps:
            assert step.phase == "ANALYZE"

    def test_phase_report_suspicious(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[0])
        entities = dropzone_agent._extract_entities(sample_alerts[0])
        _, hypotheses = dropzone_agent._phase_strategize(
            sample_alerts[0], alert_type, entities
        )
        hypotheses[0].confidence = 0.70
        report_steps, disposition, confidence, summary = dropzone_agent._phase_report(
            sample_alerts[0], alert_type, hypotheses, []
        )
        assert disposition in ("SUSPICIOUS", "MALICIOUS", "BENIGN")
        assert 0 <= confidence <= 1

    def test_phase_report_scanner(self, sample_alerts):
        from bradlyai.services.dropzone_agent import dropzone_agent
        alert_type = dropzone_agent._classify_alert_type(sample_alerts[1])
        entities = dropzone_agent._extract_entities(sample_alerts[1])
        _, hypotheses = dropzone_agent._phase_strategize(
            sample_alerts[1], alert_type, entities
        )
        hypotheses[0].confidence = 0.90
        hypotheses[0].status = "confirmed"  # Simulate analyze phase
        report_steps, disposition, confidence, summary = dropzone_agent._phase_report(
            sample_alerts[1], alert_type, hypotheses, []
        )
        assert disposition == "BENIGN", f"Expected BENIGN, got {disposition}"

    @pytest.mark.asyncio
    async def test_full_investigation(self, sample_alerts, db_module):
        from bradlyai.services.dropzone_agent import auto_investigate_alert

        alert = sample_alerts[0]
        investigation = await auto_investigate_alert(alert, db_module)

        assert investigation.investigation_id.startswith("DZINV-")
        assert investigation.alert_id == alert.id
        assert investigation.disposition in ("BENIGN", "SUSPICIOUS", "MALICIOUS")
        assert 0 <= investigation.confidence <= 1
        assert len(investigation.oscar_steps) > 10
        assert len(investigation.hypotheses) >= 3

        # Verify all 5 OSCAR phases present
        phases = {s.phase for s in investigation.oscar_steps}
        for p in ("OBTAIN", "STRATEGIZE", "COLLECT", "ANALYZE", "REPORT"):
            assert p in phases, f"Missing OSCAR phase: {p}"

        assert investigation.duration_total_ms > 0


class TestDropzoneRouter:
    """Test the Dropzone API router."""

    def test_router_exists(self):
        from bradlyai.routers.dropzone import router
        assert router.prefix == "/dropzone"
        assert "Dropzone AI" in router.tags[0]
