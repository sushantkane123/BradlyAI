"""Real multi-source event ingestion for SIEM, XDR, EDR, and custom webhooks."""
from __future__ import annotations

import hmac
import json
import logging
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.database import get_db
from bradlyai.models.alert import AlertModel
from bradlyai.services.alert_normalizer import NormalizedAlert, normalize
from bradlyai.services.auto_closer import auto_closer
from bradlyai.services.l1_decision_engine import l1_engine
from bradlyai.services.log_ingestion import log_ingestion

logger = logging.getLogger("bradlyai.ingest")
router = APIRouter(prefix="/ingest", tags=["Real Log Ingestion"])

SUPPORTED_SOURCES = [
    "wazuh", "splunk", "sentinel", "microsoft_sentinel", "defender",
    "microsoft_defender", "crowdstrike", "falcon", "elastic", "elk",
    "elasticsearch", "siem", "xdr", "edr", "jira", "generic",
]


class EventIngestRequest(BaseModel):
    """One event envelope that works across supported SIEM, XDR, EDR, and custom sources."""

    source: str = Field(description="Source name, such as sentinel, crowdstrike, defender, elastic, or wazuh")
    payload: dict[str, Any] = Field(description="Original source event; it is retained for investigation evidence")
    mode: Optional[Literal["shadow", "active"]] = Field(
        default=None,
        description="shadow stores/audits decisions only; active may apply the configured close policy",
    )


class EventBatchIngestRequest(BaseModel):
    events: list[EventIngestRequest] = Field(min_length=1, max_length=500)
    mode: Optional[Literal["shadow", "active"]] = None


def _verify_ingestion_secret(x_ingestion_key: Optional[str]) -> None:
    """Require a shared key only when an operator configures one.

    Production deployments should use this behind TLS, IP allow-listing, and ideally
    mTLS or an API gateway. Keeping it optional preserves local replay testing.
    """
    expected = settings.INGESTION_SHARED_SECRET
    if expected and not hmac.compare_digest(x_ingestion_key or "", expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-Ingestion-Key")


def _store_normalized_event(db: Session, normalized: NormalizedAlert) -> AlertModel:
    """Upsert the normalized event while retaining the full original source payload."""
    alert = db.query(AlertModel).filter(AlertModel.id == normalized.id).first()
    if alert is None:
        alert = AlertModel(id=normalized.id)
        db.add(alert)

    # Preserve lifecycle status for a case already being worked; a duplicate delivery
    # must not silently reset it to OPEN.
    if not alert.status or str(alert.status).upper() in {"NEW", "OPEN"}:
        alert.status = "OPEN"
    alert.severity = normalized.severity
    alert.title = normalized.title
    alert.endpoint = normalized.asset or "unknown"
    alert.ip = normalized.source_ip or ""
    alert.timestamp = normalized.timestamp or ""
    alert.mitre = normalized.mitre or ""
    alert.source = normalized.source
    alert.signature = normalized.signature
    # A single-tenant local/lab deployment uses the configured default tenant;
    # production connectors should set the same field from authenticated routing.
    alert.tenant_id = alert.tenant_id or settings.DEFAULT_TENANT_ID
    alert.raw_event = json.dumps(normalized.raw, default=str, separators=(",", ":"))
    if not alert.ai_confidence:
        alert.ai_confidence = "Pending"
    db.commit()
    db.refresh(alert)
    return alert


def _process_event(db: Session, request: EventIngestRequest, mode_override: Optional[str] = None) -> dict[str, Any]:
    try:
        normalized = normalize(request.source, request.payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mode = mode_override or request.mode or settings.INGESTION_DEFAULT_MODE
    alert = _store_normalized_event(db, normalized)
    decision = l1_engine.decide_sync(alert, mode=mode)

    # Persist decision context on the alert before the action/audit side effect.
    alert.ai_confidence = f"{decision.confidence:.0%}"
    if decision.decision == "ESCALATE":
        alert.status = "ESCALATED"
    elif decision.decision == "SHADOW_CLOSE":
        alert.status = "PENDING_REVIEW"
    db.commit()

    # AutoCloser records the audit event. In shadow mode it records SHADOW_CLOSE but
    # does not close local or external alerts; in active mode it follows Wazuh policy.
    action = auto_closer.apply(decision, alert_id_from_db=alert.id)
    logger.info(
        "Ingested source=%s alert=%s mode=%s decision=%s confidence=%.2f",
        normalized.source, alert.id, mode, decision.decision, decision.confidence,
    )
    return {
        "stored": True,
        "source": normalized.source,
        "mode": mode,
        "alert": normalized.to_dict(),
        "decision": decision.to_dict(),
        "action": action,
    }


@router.get("/sources")
def supported_sources() -> dict[str, Any]:
    """Expose the accepted source adapters and current safety defaults."""
    return {
        "sources": SUPPORTED_SOURCES,
        "default_mode": settings.INGESTION_DEFAULT_MODE,
        "demo_data_enabled": settings.DEMO_DATA_ENABLED,
        "shared_secret_required": bool(settings.INGESTION_SHARED_SECRET),
    }


@router.post("/events")
def ingest_event(
    request: EventIngestRequest,
    x_ingestion_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Persist and triage one real SIEM/XDR/EDR/custom event.

    Start with mode=shadow. Only an operator-approved active policy can take actions.
    """
    _verify_ingestion_secret(x_ingestion_key)
    return _process_event(db, request)


@router.post("/events/batch")
def ingest_event_batch(
    request: EventBatchIngestRequest,
    x_ingestion_key: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Process a bounded batch and return individual successes/errors for replay jobs."""
    _verify_ingestion_secret(x_ingestion_key)
    results: list[dict[str, Any]] = []
    for event in request.events:
        try:
            results.append(_process_event(db, event, request.mode))
        except HTTPException as exc:
            results.append({"stored": False, "source": event.source, "error": exc.detail})
        except Exception as exc:  # Keep one malformed source event from dropping an entire replay batch.
            logger.exception("Event ingestion failed for source=%s", event.source)
            results.append({"stored": False, "source": event.source, "error": str(exc)})
    return {
        "total": len(request.events),
        "stored": sum(1 for result in results if result.get("stored")),
        "failed": sum(1 for result in results if not result.get("stored")),
        "results": results,
    }


# Legacy text/file ingestion remains available for lab log replay.
@router.post("/logs/text")
async def ingest_text_logs(logs: str = Form(...)):
    if not logs.strip():
        raise HTTPException(400, "No logs provided")
    return log_ingestion.ingest_text(logs)


@router.post("/logs/json")
async def ingest_json_logs(logs: list[dict[str, Any]]):
    if not logs:
        raise HTTPException(400, "Empty log array")
    return log_ingestion.ingest_json(logs)


@router.post("/logs/upload")
async def upload_log_file(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")
    if file.filename and file.filename.endswith(".json"):
        try:
            data = json.loads(content)
            return log_ingestion.ingest_json(data if isinstance(data, list) else [data])
        except json.JSONDecodeError:
            pass
    return log_ingestion.ingest_text(content)


@router.get("/events")
async def get_ingested_events(limit: int = 50):
    return {"count": len(log_ingestion.events), "events": log_ingestion.get_events(limit)}


@router.get("/alerts")
async def get_real_alerts(limit: int = 100):
    return {"count": len(log_ingestion.alerts), "alerts": log_ingestion.get_alerts(limit)}


@router.post("/clear")
async def clear_data():
    log_ingestion.clear()
    return {"status": "success", "message": "All in-memory replay data cleared"}
