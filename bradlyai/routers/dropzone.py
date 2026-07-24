"""
Dropzone-style Autonomous SOC Router.

Mirrors Dropzone AI's API surface for autonomous L1 investigation:
- POST /dropzone/investigate — Full autonomous OSCAR investigation
- POST /dropzone/investigate/all — Auto-investigate all pending alerts
- GET  /dropzone/investigations — List all autonomous investigations
- GET  /dropzone/investigations/{id} — Get full investigation with OSCAR steps
- GET  /dropzone/dashboard — Dropzone-style investigation dashboard stats
- POST /dropzone/webhook/alert — Receive and auto-investigate external alerts
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from bradlyai.database import SessionLocal, get_db
from bradlyai.models.alert import AlertModel
from bradlyai.models.investigation import InvestigationModel
from bradlyai.services.auth import get_current_user, require_permission
from bradlyai.services.dropzone_agent import (
    dropzone_agent,
    auto_investigate_alert,
    auto_investigate_batch,
    DropzoneInvestigation,
)
from bradlyai.services.alert_normalizer import normalize

logger = logging.getLogger("bradlyai.dropzone_router")
router = APIRouter(prefix="/dropzone", tags=["Dropzone AI — Autonomous SOC"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AlertPayload(BaseModel):
    source: str = Field(..., description="splunk / sentinel / defender / crowdstrike / wazuh / elastic / generic")
    payload: dict = Field(..., description="Raw alert from source system")
    auto_investigate: bool = Field(True, description="If true, immediately trigger full OSCAR investigation")


class BatchPayload(BaseModel):
    alerts: list[AlertPayload]


class WebhookPayload(BaseModel):
    """External webhook alert — like Dropzone's connector-based ingestion."""
    source: str
    alert_id: str
    alert_name: str
    severity: str = "MEDIUM"
    entities: Optional[dict] = None
    raw_event: Optional[dict] = None


# ── Helper ───────────────────────────────────────────────────────────────────

def _to_investigation_dict(inv: InvestigationModel) -> dict[str, Any]:
    return {
        "id": inv.id,
        "alert_id": inv.alert_id,
        "tenant_id": inv.tenant_id,
        "status": inv.status,
        "disposition": inv.recommendation,
        "confidence": inv.confidence,
        "summary": inv.summary,
        "plan": inv.plan_json or [],
        "evidence": inv.evidence_json or [],
        "hypotheses": inv.hypotheses_json or [],
        "policy": inv.policy_json or {},
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
    }


# ── Core: Autonomous Investigation ───────────────────────────────────────────

@router.post("/investigate/{alert_id}")
async def investigate_alert(
    alert_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Run a full autonomous OSCAR investigation on a specific alert.

    This is the Dropzone-style endpoint: the AI agent autonomously:
    1. Obtains and normalizes the alert
    2. Strategizes by formulating multiple hypotheses
    3. Collects evidence from available security tools
    4. Analyzes evidence recursively until a conclusion is reached
    5. Reports with disposition, confidence, and recommended actions

    NO human in the critical path — the AI handles the full L1 workflow.
    """
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        investigation = await auto_investigate_alert(alert, db)
        return _dropzone_to_dict(investigation)
    except Exception as e:
        logger.exception(f"Dropzone investigation failed for alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.post("/investigate/all")
async def investigate_all_pending(
    limit: int = Query(default=50, ge=1, le=200),
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Auto-investigate ALL pending/uninvestigated alerts — Dropzone-style batch triage.

    This mirrors Dropzone's behavior where every alert in the queue gets
    automatically investigated. Return results for immediate feedback,
    and can also run in background for larger batches.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    # Find alerts that haven't been investigated by the Dropzone agent yet
    pending_alerts = db.query(AlertModel).filter(
        AlertModel.created_at >= cutoff
    ).order_by(AlertModel.severity.desc()).limit(limit).all()

    if not pending_alerts:
        return {"message": "No pending alerts to investigate", "count": 0, "results": []}

    results = []
    for alert in pending_alerts:
        try:
            investigation = await auto_investigate_alert(alert, db)
            results.append(_dropzone_to_dict(investigation))
        except Exception as e:
            logger.error(f"Batch investigation failed for {alert.id}: {e}")
            results.append({"alert_id": alert.id, "error": str(e)})

    return {
        "total": len(pending_alerts),
        "investigated": len([r for r in results if "error" not in r]),
        "errors": len([r for r in results if "error" in r]),
        "results": results,
    }


@router.post("/ingest-and-investigate")
async def ingest_and_investigate(
    payload: AlertPayload,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Dropzone-style: ingest an alert AND immediately run a full autonomous investigation.

    This is the primary entry point for real-time alert processing —
    mirroring how Dropzone AI receives alerts from SIEM/XDR and
    immediately begins investigating them.
    """
    try:
        normalized = normalize(payload.source, payload.payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid alert: {str(e)}")

    # Store the alert
    alert = AlertModel(
        id=normalized.id,
        title=normalized.title,
        severity=normalized.severity,
        source=payload.source,
        endpoint=normalized.endpoint or "unknown",
        ip=normalized.ip or "unknown",
        mitre=normalized.mitre or "",
        raw_event=str(payload.payload),
        signature=normalized.signature or "",
        status="NEW",
        tenant_id="default",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    if not payload.auto_investigate:
        return {"alert_id": alert.id, "status": "stored", "investigation": None}

    # Immediately investigate
    try:
        investigation = await auto_investigate_alert(alert, db)
        return _dropzone_to_dict(investigation)
    except Exception as e:
        logger.exception(f"Auto-investigation failed: {e}")
        return {"alert_id": alert.id, "status": "stored", "investigation_error": str(e)}


# ── Investigation History ────────────────────────────────────────────────────

@router.get("/investigations")
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    disposition: Optional[str] = Query(None, description="Filter: BENIGN / SUSPICIOUS / MALICIOUS"),
    since_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List all Dropzone autonomous investigations."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    query = db.query(InvestigationModel).filter(
        InvestigationModel.created_at >= cutoff
    )
    if disposition:
        query = query.filter(InvestigationModel.recommendation == disposition)
    items = query.order_by(InvestigationModel.created_at.desc()).limit(limit).all()
    return {
        "count": len(items),
        "since": cutoff.isoformat(),
        "investigations": [_to_investigation_dict(inv) for inv in items],
    }


@router.get("/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Get a full investigation with all OSCAR steps, evidence, and hypotheses.

    Glass-box transparency: every step, query, and finding is visible.
    """
    inv = db.query(InvestigationModel).filter(
        InvestigationModel.id == investigation_id
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return _to_investigation_dict(inv)


# ── Dashboard / Stats ────────────────────────────────────────────────────────

@router.get("/dashboard")
async def dropzone_dashboard(
    since_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Dropzone-style investigation dashboard showing:
    - Total alerts investigated
    - Disposition breakdown (benign/suspicious/malicious)
    - Average investigation time
    - Auto-close rate
    - Connector status
    - Investigation throughput
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    investigations = db.query(InvestigationModel).filter(
        InvestigationModel.created_at >= cutoff
    ).all()

    total = len(investigations)
    benign = sum(1 for i in investigations if i.recommendation == "BENIGN")
    suspicious = sum(1 for i in investigations if i.recommendation == "SUSPICIOUS")
    malicious = sum(1 for i in investigations if i.recommendation == "MALICIOUS")

    # Average duration from policy_json
    durations = []
    for inv in investigations:
        policy = inv.policy_json or {}
        dur = policy.get("total_duration_ms", 0)
        if dur:
            durations.append(dur)

    avg_duration_ms = sum(durations) / len(durations) if durations else 0

    # Data sources used
    all_sources: dict[str, int] = {}
    for inv in investigations:
        policy = inv.policy_json or {}
        for src in policy.get("data_sources", []):
            all_sources[src] = all_sources.get(src, 0) + 1

    # Auto-close rate
    auto_close_rate = round(benign / total, 3) if total > 0 else 0

    # Hourly throughput
    hourly: dict[str, int] = {}
    for inv in investigations:
        if inv.created_at:
            hour_key = inv.created_at.strftime("%Y-%m-%dT%H:00")
            hourly[hour_key] = hourly.get(hour_key, 0) + 1

    # Connector status
    from bradlyai.config import settings
    connector_status = {
        "edr": {"enabled": settings.EDR_ENABLED, "provider": settings.EDR_PROVIDER, "dry_run": settings.EDR_DRY_RUN},
        "identity": {"enabled": settings.IDENTITY_ENABLED, "provider": settings.IDENTITY_PROVIDER, "dry_run": settings.IDENTITY_DRY_RUN},
        "network": {"enabled": settings.NETWORK_ENABLED, "provider": settings.NETWORK_PROVIDER, "dry_run": settings.NETWORK_DRY_RUN},
        "threat_intel": {"enabled": settings.THREATINTEL_ENABLED},
        "siem": {
            "wazuh": settings.WAZUH_ENABLED,
            "sentinel": settings.SIEM_SENTINEL_ENABLED if hasattr(settings, "SIEM_SENTINEL_ENABLED") else False,
            "splunk": settings.SIEM_SPLUNK_ENABLED if hasattr(settings, "SIEM_SPLUNK_ENABLED") else False,
            "elastic": settings.SIEM_ELASTIC_ENABLED if hasattr(settings, "SIEM_ELASTIC_ENABLED") else False,
        },
    }

    return {
        "period_hours": since_hours,
        "total_investigations": total,
        "disposition_breakdown": {
            "BENIGN": {"count": benign, "pct": round(benign / total * 100, 1) if total else 0},
            "SUSPICIOUS": {"count": suspicious, "pct": round(suspicious / total * 100, 1) if total else 0},
            "MALICIOUS": {"count": malicious, "pct": round(malicious / total * 100, 1) if total else 0},
        },
        "auto_close_rate": auto_close_rate,
        "avg_investigation_time_ms": round(avg_duration_ms, 0),
        "avg_investigation_time_seconds": round(avg_duration_ms / 1000, 1),
        "data_sources_used": all_sources,
        "connector_status": connector_status,
        "hourly_throughput": hourly,
        "methodology": "OSCAR (Obtain → Strategize → Collect → Analyze → Report)",
        "recursive_reasoning": True,
    }


# ── Webhook endpoint for SIEM/SOAR integration ──────────────────────────────

@router.post("/webhook/alert")
async def webhook_alert(
    payload: WebhookPayload,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Webhook endpoint for SIEM, XDR, EDR, and SOAR tools to send alerts.

    Like Dropzone's connector architecture, this accepts alerts from any tool,
    normalizes them, stores them, and triggers autonomous investigation.
    """
    alert = AlertModel(
        id=payload.alert_id or f"WH-{datetime.now(timezone.utc).timestamp()}",
        title=payload.alert_name,
        severity=payload.severity.upper(),
        source=payload.source,
        endpoint=(payload.entities or {}).get("hostname", "unknown"),
        ip=(payload.entities or {}).get("source_ip", "unknown"),
        mitre=(payload.entities or {}).get("mitre_technique", ""),
        raw_event=str(payload.raw_event or payload.model_dump()),
        signature=f"{payload.source}:{payload.alert_name[:50]}",
        status="NEW",
        tenant_id="default",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Fire and forget investigation in background
    if background_tasks:
        background_tasks.add_task(_background_investigate, alert.id)
    else:
        # Run synchronously
        try:
            investigation = await auto_investigate_alert(alert, db)
            return _dropzone_to_dict(investigation)
        except Exception as e:
            return {"alert_id": alert.id, "status": "stored", "investigation_error": str(e)}

    return {"alert_id": alert.id, "status": "accepted", "investigation": "pending (background)"}


async def _background_investigate(alert_id: str):
    """Background task to investigate an alert."""
    db = SessionLocal()
    try:
        alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
        if alert:
            await auto_investigate_alert(alert, db)
    except Exception as e:
        logger.error(f"Background investigation failed for {alert_id}: {e}")
    finally:
        db.close()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _dropzone_to_dict(inv: DropzoneInvestigation) -> dict[str, Any]:
    """Convert DropzoneInvestigation dataclass to API response dict."""
    return {
        "investigation_id": inv.investigation_id,
        "alert_id": inv.alert_id,
        "status": inv.status,
        "disposition": inv.disposition,
        "confidence": inv.confidence,
        "summary": inv.summary,
        "entities": inv.entities,
        "hypotheses": [
            {
                "id": h.id,
                "statement": h.statement,
                "likelihood": h.likelihood,
                "confidence": h.confidence,
                "supporting_evidence": h.supporting_evidence,
                "contradicting_evidence": h.contradicting_evidence,
                "status": h.status,
            }
            for h in inv.hypotheses
        ],
        "oscar_steps": [
            {
                "phase": s.phase,
                "step": s.step_number,
                "task": s.task,
                "status": s.status,
                "finding": s.finding,
                "data_sources_queried": s.data_sources_queried,
                "evidence_collected": s.evidence_collected,
                "duration_ms": s.duration_ms,
            }
            for s in inv.oscar_steps
        ],
        "evidence_summary": inv.evidence_summary,
        "data_sources": inv.data_sources,
        "duration_total_ms": inv.duration_total_ms,
        "duration_total_seconds": round(inv.duration_total_ms / 1000, 2),
        "escalation_reason": inv.escalation_reason,
        "recommended_actions": inv.recommended_actions,
        "raw_evidence_links": inv.raw_evidence_links,
        "created_at": inv.created_at,
        "completed_at": inv.completed_at,
        "methodology": "OSCAR (Obtain → Strategize → Collect → Analyze → Report)",
        "recursive_reasoning": True,
    }
