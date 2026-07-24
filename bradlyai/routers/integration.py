"""
BradlyAI — Wazuh SIEM Integration Router
Full lifecycle: Alert → Investigate → Evidence → Closure
"""
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from bradlyai.services.detection_engine import detection_engine
from bradlyai.services.log_ingestion import log_ingestion
from bradlyai.services.alert_normalizer import normalize
from bradlyai.services.l1_decision_engine import l1_engine
from bradlyai.services.auto_closer import auto_closer

from bradlyai.services.incident_manager import (
    incident_manager, Incident, IncidentStatus, IncidentSeverity,
)

logger = logging.getLogger("bradlyai.integration")
router = APIRouter(prefix="/integration", tags=["SIEM Integration"])


# ── Wazuh Schemas ──────────────────────────────────────────────────────

class WazuhRule(BaseModel):
    level: int
    description: str
    id: str = ""
    mitre: Optional[Dict[str, List[str]]] = None
    firedtimes: int = 1


class WazuhAgent(BaseModel):
    id: str = "000"
    name: str = "unknown"
    ip: str = ""


class WazuhAlert(BaseModel):
    timestamp: Optional[str] = None
    rule: WazuhRule
    agent: WazuhAgent
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    location: Optional[str] = None
    id: Optional[str] = None


class WazuhWebhookPayload(BaseModel):
    alerts: List[WazuhAlert] = Field(default_factory=list)


# ── RESPONSE SCHEMAS ───────────────────────────────────────────────────

class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    source: str
    source_agent: str
    source_ip: str
    status: str
    created_at: str
    updated_at: str
    closed_at: str
    mitre_technique: str
    investigation_summary: str
    resolution: str
    closure_report: str
    evidence_count: int
    investigation_steps: List[dict]
    evidence_items: List[dict]
    containment_actions: List[str]


def incident_to_response(inc: Incident) -> dict:
    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "source": inc.source,
        "source_alert_id": inc.source_alert_id,
        "source_agent": inc.source_agent,
        "source_ip": inc.source_ip,
        "status": inc.status,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "closed_at": inc.closed_at,
        "assigned_to": inc.assigned_to,
        "mitre_technique": inc.mitre_technique,
        "investigation_summary": inc.investigation_summary,
        "resolution": inc.resolution,
        "closure_report": inc.closure_report,
        "evidence_count": len(inc.evidence_items),
        "investigation_steps": [
            {"order": s.order, "action": s.action, "status": s.status, "result": s.result, "timestamp": s.timestamp}
            for s in inc.investigation_steps
        ],
        "evidence_items": [
            {"id": e.id, "type": e.evidence_type, "title": e.title, "description": e.description, "source": e.source, "timestamp": e.timestamp}
            for e in inc.evidence_items
        ],
        "containment_actions": inc.containment_actions,
    }


def _wazuh_alert_to_dict(alert: WazuhAlert) -> dict:
    return {
        "id": alert.id,
        "timestamp": alert.timestamp,
        "rule": alert.rule.model_dump(),
        "agent": alert.agent.model_dump(),
        "data": alert.data,
        "location": alert.location,
    }


# ── INGEST: Wazuh Webhook ─────────────────────────────────────────────

@router.post("/wazuh/ingest")
async def wazuh_webhook_ingest(payload: WazuhWebhookPayload, run_l1: bool = Query(True, description="Run L1 Agent decision on each alert")):
    """
    STEP 1: Receive alerts from Wazuh SIEM via webhook.

    NEW: Each alert now runs through the L1 Agent FIRST. If the agent
    decides CLOSE (it's a false positive or duplicate), the alert is
    archived in Wazuh via the Wazuh Manager API (if enabled). If the
    agent decides ESCALATE, a BradlyAI incident is created for L2 review.

    Configure Wazuh ossec.conf:
    ```xml
    <integration>
      <name>custom-webhook</name>
      <hook_url>http://BRADLYAI:8000/api/v1/integration/wazuh/ingest</hook_url>
      <level>3</level>
    </integration>
    ```
    """
    if not payload.alerts:
        raise HTTPException(400, "No alerts in payload")

    results = []
    l1_decisions = {"CLOSE": 0, "ESCALATE": 0, "SHADOW_CLOSE": 0}
    new_incidents = []

    for alert in payload.alerts:
        alert_dict = _wazuh_alert_to_dict(alert)

        # Build event for detection engine
        event = {
            "message": alert.rule.description,
            "source": alert.agent.name,
            "host": alert.agent.name,
            "src_ip": alert.agent.ip,
            "ip": alert.agent.ip,
            "raw": alert.model_dump_json(),
            "wazuh_level": alert.rule.level,
            "wazuh_rule_id": alert.rule.id,
        }
        bradly_alert = detection_engine.detect(event)
        log_ingestion.ingest_text(alert.rule.description)

        result = {
            "wazuh_alert_id": alert.id,
            "wazuh_rule_id": alert.rule.id,
            "wazuh_level": alert.rule.level,
            "wazuh_description": alert.rule.description,
            "agent": alert.agent.name,
            "l1_decision": None,
        }

        # === NEW: L1 Agent decision ===
        if run_l1:
            try:
                # Normalize Wazuh alert into L1 Agent's expected format
                normalized = normalize("wazuh", alert_dict)
                decision = l1_engine.decide_sync(normalized, mode="active")
                l1_decisions[decision.decision] = l1_decisions.get(decision.decision, 0) + 1
                result["l1_decision"] = decision.decision
                result["l1_confidence"] = decision.confidence
                result["l1_reason"] = decision.reason[:200]
                result["l1_signals"] = [s["name"] for s in decision.signals]

                # Apply decision (this also calls Wazuh API if enabled + CLOSE)
                if decision.decision in ("CLOSE", "ESCALATE"):
                    applied = auto_closer.apply(decision)
                    result["l1_action"] = applied.get("action_taken")
                    result["l1_audit_id"] = applied.get("audit_id")
                    if applied.get("wazuh_result"):
                        result["l1_wazuh_result"] = applied["wazuh_result"]

                # If agent decided CLOSE, don't create incident (it's already handled)
                if decision.decision == "CLOSE":
                    if bradly_alert:
                        result["bradly_detected"] = True
                        result["bradly_alert_id"] = bradly_alert.id
                    continue  # Skip incident creation
            except Exception as e:
                logger.exception(f"L1 Agent error for {alert.id}: {e}")
                result["l1_error"] = str(e)
                # Fall through to incident creation

        # === Original flow: create incident for HIGH/CRITICAL ===
        if bradly_alert:
            result["bradly_detected"] = True
            result["bradly_alert_id"] = bradly_alert.id
            result["bradly_severity"] = bradly_alert.severity
            result["bradly_rule"] = bradly_alert.rule_id
            result["bradly_mitre"] = bradly_alert.mitre

            if bradly_alert.severity in ("CRITICAL", "HIGH"):
                inc = incident_manager.create_from_wazuh(alert_dict, {
                    "id": bradly_alert.id, "title": bradly_alert.title,
                    "rule_id": bradly_alert.rule_id, "severity": bradly_alert.severity,
                    "mitre": bradly_alert.mitre,
                })
                new_incidents.append(inc.id)
                result["incident_created"] = inc.id
        else:
            result["bradly_detected"] = False

        results.append(result)

    logger.info(
        f"Wazuh ingest: {len(payload.alerts)} alerts | "
        f"L1: close={l1_decisions['CLOSE']} escalate={l1_decisions['ESCALATE']} | "
        f"incidents created={len(new_incidents)}"
    )

    return {
        "status": "PROCESSED",
        "events_received": len(payload.alerts),
        "l1_decisions": l1_decisions,
        "incidents_created": new_incidents,
        "results": results,
    }


# ── INCIDENT: List / Create / Get ─────────────────────────────────────

@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List all incidents with optional filters."""
    incidents = incident_manager.list_incidents(status=status, severity=severity)
    return {
        "count": len(incidents),
        "stats": incident_manager.get_stats(),
        "incidents": [incident_to_response(inc) for inc in incidents],
    }


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get full incident details including investigation, evidence, and closure report."""
    inc = incident_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return incident_to_response(inc)


@router.post("/incidents")
async def create_incident(
    title: str = Query(...),
    severity: str = Query("HIGH"),
    source: str = Query("manual"),
    source_agent: str = Query("unknown"),
    source_ip: str = Query(""),
    mitre: str = Query("TBD"),
):
    """Manually create an incident (for testing or manual triage)."""
    inc = Incident(
        id=f"INC-{__import__('uuid').uuid4().hex[:8].upper()}",
        title=title, severity=severity, source=source,
        source_agent=source_agent, source_ip=source_ip,
        mitre_technique=mitre,
        status=IncidentStatus.OPEN,
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    inc.investigation_steps = incident_manager._build_investigation_plan(inc)
    incident_manager.incidents[inc.id] = inc
    return incident_to_response(inc)


# ── INVESTIGATE: Start Investigation ───────────────────────────────────

@router.post("/incidents/{incident_id}/investigate")
async def start_investigation(incident_id: str):
    """
    STEP 2: Launch the autonomous investigation.

    BradlyAI will:
    1. Correlate logs from the source endpoint
    2. Map MITRE ATT&CK TTPs
    3. Generate process tree & memory forensics
    4. Identify affected assets
    5. Extract IoCs & generate YARA rules
    6. Auto-contain the threat
    7. Verify containment
    """
    try:
        inc = incident_manager.start_investigation(incident_id)
        return {
            "status": inc.status,
            "incident_id": inc.id,
            "investigation_summary": inc.investigation_summary,
            "steps_completed": sum(1 for s in inc.investigation_steps if s.status == "completed"),
            "total_steps": len(inc.investigation_steps),
            "evidence_collected": len(inc.evidence_items),
            "investigation_steps": [
                {"order": s.order, "action": s.action, "status": s.status, "result": s.result}
                for s in inc.investigation_steps
            ],
        }
    except ValueError as e:
        raise HTTPException(404, str(e))


# ── EVIDENCE: Add / List ──────────────────────────────────────────────

@router.post("/incidents/{incident_id}/evidence")
async def add_evidence(
    incident_id: str,
    etype: str = Query(..., alias="type"),
    title: str = Query(...),
    description: str = Query(...),
    source: str = Query("manual"),
):
    """Manually add evidence to an incident."""
    try:
        ev = incident_manager.add_evidence(incident_id, etype, title, description, source)
        return {"status": "ADDED", "evidence_id": ev.id, "evidence_type": ev.evidence_type}
    except ValueError as e:
        raise HTTPException(404, str(e))


@router.get("/incidents/{incident_id}/evidence")
async def list_evidence(incident_id: str):
    """List all evidence for an incident."""
    inc = incident_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return {
        "incident_id": inc.id,
        "count": len(inc.evidence_items),
        "evidence": [
            {"id": e.id, "type": e.evidence_type, "title": e.title,
             "description": e.description, "source": e.source, "timestamp": e.timestamp}
            for e in inc.evidence_items
        ],
    }


# ── CLOSE: Ticket Closure ─────────────────────────────────────────────

@router.post("/incidents/{incident_id}/close")
async def close_incident(
    incident_id: str,
    resolution: str = Query("", description="Custom resolution message"),
):
    """
    STEP 3: Close the incident ticket.

    Prerequisites:
    - Incident must be in CONTAINED status (investigation must be run first)
    
    Generates a full closure report with:
    - Investigation summary
    - All evidence items
    - Containment actions taken
    - Resolution statement
    """
    try:
        inc = incident_manager.close_incident(incident_id, resolution)
        return {
            "status": "CLOSED",
            "incident_id": inc.id,
            "closed_at": inc.closed_at,
            "resolution": inc.resolution,
            "closure_report": inc.closure_report,
            "evidence_collected": len(inc.evidence_items),
            "containment_actions": inc.containment_actions,
        }
    except ValueError as e:
        raise HTTPException(400, str(e))


# ── FULL PIPELINE: Wazuh Alert → Investigate → Close ─────────────────

class WazuhAlertInput(BaseModel):
    """Simplified Wazuh alert for demo/testing."""
    rule_level: int = Field(12, ge=0, le=15)
    rule_description: str = "Suspicious PowerShell execution detected"
    agent_name: str = "WEB-SRV01"
    agent_ip: str = "192.168.1.100"
    mitre_id: str = "T1059.001"
    auto_close: bool = Field(True, description="Auto-run investigation and close")


@router.post("/wazuh/full-pipeline")
async def wazuh_full_pipeline(input_data: WazuhAlertInput):
    """
    🚀 COMPLETE PIPELINE: Wazuh Alert → Ingestion → Incident → Investigation → Evidence → Closure

    Single endpoint that runs the entire autonomous SOC workflow.
    """
    # Step 1: Create Wazuh alert
    alert = WazuhAlert(
        timestamp=datetime.now(timezone.utc).isoformat(),
        rule=WazuhRule(level=input_data.rule_level, description=input_data.rule_description, id="100001", firedtimes=1,
                       mitre={"id": [input_data.mitre_id], "tactic": ["Execution"]}),
        agent=WazuhAgent(name=input_data.agent_name, ip=input_data.agent_ip),
        data={"srcip": input_data.agent_ip, "action": "blocked"},
    )

    # Step 2: Ingest + detect
    event = {
        "message": input_data.rule_description,
        "source": input_data.agent_name,
        "host": input_data.agent_name,
        "src_ip": input_data.agent_ip,
        "ip": input_data.agent_ip,
    }
    bradly_alert = detection_engine.detect(event)
    log_ingestion.ingest_text(input_data.rule_description)

    # Step 3: Create incident
    alert_dict = _wazuh_alert_to_dict(alert)
    inc = incident_manager.create_from_wazuh(alert_dict, {
        "id": bradly_alert.id, "title": bradly_alert.title,
        "rule_id": bradly_alert.rule_id, "severity": bradly_alert.severity,
        "mitre": bradly_alert.mitre,
    } if bradly_alert else None)

    # Step 4: Investigate
    inc = incident_manager.start_investigation(inc.id)

    # Step 5: Close
    if input_data.auto_close and inc.status == IncidentStatus.CONTAINED:
        inc = incident_manager.close_incident(inc.id, f"Autonomous pipeline: {input_data.rule_description} on {input_data.agent_name} fully contained and resolved by BradlyAI.")

    return {
        "pipeline": "Wazuh → Investigate → Evidence → Closure",
        "status": inc.status,
        "wazuh_alert": {
            "rule": input_data.rule_description,
            "level": input_data.rule_level,
            "agent": input_data.agent_name,
            "ip": input_data.agent_ip,
        },
        "bradly_detection": {
            "detected": bradly_alert is not None,
            "alert_id": bradly_alert.id if bradly_alert else None,
            "severity": bradly_alert.severity if bradly_alert else "NONE",
        } if bradly_alert else None,
        "incident": incident_to_response(inc),
        "evidence_collected": len(inc.evidence_items),
        "closure_report": inc.closure_report if inc.status == IncidentStatus.CLOSED else None,
    }


# ── TEST WEBHOOK: Simulate Wazuh calling us ──────────────────────────

class WazuhTestWebhookInput(BaseModel):
    """Synthetic Wazuh alert payload for testing the integration end-to-end."""
    rule_level: int = Field(12, ge=0, le=15)
    rule_id: str = "100001"
    rule_description: str = "Suspicious PowerShell execution detected"
    agent_name: str = "WEB-SRV01"
    agent_ip: str = "192.168.1.100"
    mitre_id: str = "T1059.001"
    source_ip: Optional[str] = "10.0.0.50"


@router.post("/wazuh/test-webhook")
async def wazuh_test_webhook(input_data: WazuhTestWebhookInput):
    """Simulate a Wazuh webhook call. Runs through the FULL pipeline.

    This is what would happen if Wazuh sent a real alert to BradlyAI:
      1. Wazuh webhook received
      2. L1 Agent decision (CLOSE / ESCALATE)
      3. If CLOSE + Wazuh API enabled → archive alert in Wazuh
      4. If ESCALATE → create incident in BradlyAI

    Use this to test your Wazuh integration BEFORE pointing Wazuh at it.
    """
    payload = WazuhWebhookPayload(alerts=[
        WazuhAlert(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule=WazuhRule(level=input_data.rule_level, description=input_data.rule_description, id=input_data.rule_id, firedtimes=1),
            agent=WazuhAgent(name=input_data.agent_name, ip=input_data.agent_ip),
            data={"srcip": input_data.source_ip or input_data.agent_ip, "action": "blocked"},
            id=input_data.rule_id,
        )
    ])
    return await wazuh_webhook_ingest(payload)


# ── HEALTH ─────────────────────────────────────────────────────────────

@router.get("/wazuh/health")
async def wazuh_health():
    """Health check for Wazuh integration + incident management."""
    return {
        "status": "operational",
        "connector": "Wazuh SIEM ↔ BradlyAI Full Pipeline",
        "version": "2.0.0",
        "events_ingested": len(log_ingestion.events),
        "alerts_detected": len(log_ingestion.alerts),
        "detection_rules_active": detection_engine.rule_count,
        "incident_stats": incident_manager.get_stats(),
    }
