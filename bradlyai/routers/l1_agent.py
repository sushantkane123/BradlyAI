"""BradlyAI L1 Agent Router — REST API for the autonomous L1 SOC Agent."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.models.audit_log import AuditLogModel
from bradlyai.models.whitelist_entry import WhitelistEntryModel
from bradlyai.models.feedback import FeedbackModel
from bradlyai.services.alert_normalizer import normalize, NormalizedAlert
from bradlyai.services.l1_decision_engine import l1_engine
from bradlyai.services.auto_closer import auto_closer
from bradlyai.services.feedback_loop import feedback_loop
from bradlyai.services.whitelist import whitelist_service

logger = logging.getLogger("bradlyai.l1_router")
router = APIRouter(prefix="/l1", tags=["L1 Agent"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AlertInput(BaseModel):
    source: str = Field(..., description="splunk / wazuh / jira / bradlyai")
    payload: dict = Field(..., description="Raw alert from source system")
    mode: Optional[str] = Field("active", description="active (auto-close) or shadow (decide-only)")


class BatchInput(BaseModel):
    alerts: List[AlertInput]
    mode: Optional[str] = "active"


class WhitelistCreate(BaseModel):
    entry_type: str
    match_value: str
    name: Optional[str] = ""
    description: Optional[str] = ""
    match_field: Optional[str] = None
    match_pattern: str = "exact"
    severity_filter: Optional[List[str]] = None
    source_filter: Optional[List[str]] = None
    ttl_seconds: Optional[int] = None
    created_by: Optional[str] = "human"


class ReopenInput(BaseModel):
    reviewer: str
    reason: str


class ConfirmInput(BaseModel):
    reviewer: str
    note: Optional[str] = ""


# ── Process alerts ──────────────────────────────────────────────────────────

@router.post("/process-alert")
async def process_alert(input_data: AlertInput):
    """Process a single alert. Returns the L1 Agent's decision."""
    try:
        normalized = normalize(input_data.source, input_data.payload)
    except ValueError as e:
        raise HTTPException(400, str(e))

    mode = input_data.mode or "active"
    if mode not in ("active", "shadow"):
        raise HTTPException(400, "mode must be 'active' or 'shadow'")

    # Use async path with LLM if available, sync otherwise
    if ll1_uses_llm():
        decision = await l1_engine.decide_async(normalized, mode=mode)
    else:
        decision = l1_engine.decide_sync(normalized, mode=mode)

    # Apply the decision (or skip if shadow)
    if mode == "active":
        result = auto_closer.apply(decision)
        decision_dict = decision.to_dict()
        decision_dict["applied"] = result
    else:
        decision_dict = decision.to_dict()
        decision_dict["applied"] = {"action_taken": "shadow_no_action"}

    return decision_dict


@router.post("/process-batch")
async def process_batch(input_data: BatchInput):
    """Process a batch of alerts (queue drained periodically)."""
    results = []
    closed = 0
    escalated = 0
    errors = 0
    mode = input_data.mode or "active"

    for item in input_data.alerts:
        try:
            normalized = normalize(item.source, item.payload)
            decision = l1_engine.decide_sync(normalized, mode=mode)
            if mode == "active":
                applied = auto_closer.apply(decision)
                decision_dict = decision.to_dict()
                decision_dict["applied"] = applied
                if applied.get("alert_closed"):
                    closed += 1
                else:
                    escalated += 1
            else:
                decision_dict = decision.to_dict()
                decision_dict["applied"] = {"action_taken": "shadow_no_action"}
                if decision.decision == "SHADOW_CLOSE":
                    closed += 1
                else:
                    escalated += 1
            results.append(decision_dict)
        except Exception as e:
            logger.exception(f"Batch item failed: {e}")
            errors += 1
            results.append({"error": str(e), "source": item.source})

    return {
        "total": len(input_data.alerts),
        "closed": closed,
        "escalated": escalated,
        "errors": errors,
        "mode": mode,
        "results": results,
    }


# ── Human override ──────────────────────────────────────────────────────────

@router.post("/{alert_id}/reopen")
async def reopen_alert(alert_id: str, input_data: ReopenInput):
    """Human disagrees with auto-close — reopen the alert and record feedback."""
    return feedback_loop.reopen_alert(alert_id, input_data.reviewer, input_data.reason)


@router.post("/{alert_id}/confirm")
async def confirm_close(alert_id: str, input_data: ConfirmInput):
    """Human confirms the auto-close was correct."""
    return feedback_loop.confirm_fp(alert_id, input_data.reviewer, input_data.note)


# ── Audit & stats ───────────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit(
    since_hours: int = Query(24, ge=1, le=8760),
    limit: int = Query(100, ge=1, le=1000),
    decision: Optional[str] = Query(None, description="Filter by CLOSE / ESCALATE / SHADOW_CLOSE"),
    mode: Optional[str] = Query(None),
):
    """Audit log of L1 Agent decisions."""
    db: Session = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        q = db.query(AuditLogModel).filter(AuditLogModel.timestamp >= cutoff)
        if decision:
            q = q.filter(AuditLogModel.decision == decision)
        if mode:
            q = q.filter(AuditLogModel.mode == mode)
        entries = q.order_by(AuditLogModel.timestamp.desc()).limit(limit).all()
        return {
            "count": len(entries),
            "since": cutoff.isoformat(),
            "entries": [_audit_to_dict(e) for e in entries],
        }
    finally:
        db.close()


@router.get("/stats")
async def get_stats(since_hours: int = Query(24, ge=1, le=8760)):
    """Aggregate statistics for the L1 Agent."""
    db: Session = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        decisions = db.query(AuditLogModel).filter(AuditLogModel.timestamp >= cutoff).all()

        total = len(decisions)
        closed = sum(1 for d in decisions if d.decision == "CLOSE")
        escalated = sum(1 for d in decisions if d.decision == "ESCALATE")
        shadow = sum(1 for d in decisions if d.decision == "SHADOW_CLOSE")
        overridden = sum(1 for d in decisions if d.overridden_at is not None)

        # Avg confidence for CLOSE decisions
        close_confs = [d.confidence for d in decisions if d.decision == "CLOSE"]
        avg_close_conf = sum(close_confs) / len(close_confs) if close_confs else 0.0

        # By source
        by_source = {}
        for d in decisions:
            src = d.alert_source or "unknown"
            by_source.setdefault(src, {"total": 0, "closed": 0})
            by_source[src]["total"] += 1
            if d.decision == "CLOSE":
                by_source[src]["closed"] += 1

        # Primary signal breakdown
        signal_breakdown = {}
        for d in decisions:
            sig = d.primary_signal or "unknown"
            signal_breakdown[sig] = signal_breakdown.get(sig, 0) + 1

        return {
            "since": cutoff.isoformat(),
            "total_decisions": total,
            "closed": closed,
            "escalated": escalated,
            "shadow_decisions": shadow,
            "auto_close_rate": round(closed / total, 4) if total > 0 else 0,
            "override_rate": round(overridden / closed, 4) if closed > 0 else 0,
            "avg_close_confidence": round(avg_close_conf, 4),
            "by_source": by_source,
            "primary_signal_breakdown": signal_breakdown,
            "current_mode": _get_current_mode(),
            "threshold": l1_engine.close_threshold,
        }
    finally:
        db.close()


# ── Whitelist CRUD ──────────────────────────────────────────────────────────

@router.get("/whitelist")
async def list_whitelist(entry_type: Optional[str] = None):
    """List all whitelist entries."""
    entries = whitelist_service.list_entries(entry_type=entry_type)
    return {"count": len(entries), "entries": [_wl_to_dict(e) for e in entries]}


@router.post("/whitelist")
async def add_whitelist(input_data: WhitelistCreate):
    """Add a new whitelist entry."""
    try:
        entry = whitelist_service.add_entry(**input_data.model_dump(exclude_none=True))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _wl_to_dict(entry)


@router.delete("/whitelist/{entry_id}")
async def remove_whitelist(entry_id: int):
    """Remove a whitelist entry."""
    if not whitelist_service.remove_entry(entry_id):
        raise HTTPException(404, f"Whitelist entry {entry_id} not found")
    return {"deleted": entry_id}


@router.post("/whitelist/{entry_id}/toggle")
async def toggle_whitelist(entry_id: int, enabled: bool = Body(..., embed=True)):
    """Enable or disable a whitelist entry."""
    if not whitelist_service.toggle_entry(entry_id, enabled):
        raise HTTPException(404, f"Whitelist entry {entry_id} not found")
    return {"toggled": entry_id, "enabled": enabled}


# ── Mode & threshold ───────────────────────────────────────────────────────

_MODE = {"current": "active"}   # process-local mode state


@router.get("/mode")
async def get_mode():
    return {"mode": _MODE["current"], "threshold": l1_engine.close_threshold}


@router.post("/mode")
async def set_mode(mode: str = Body(..., embed=True),
                   threshold: Optional[float] = Body(None, embed=True)):
    """Switch between active and shadow mode. Optionally change the close threshold."""
    if mode not in ("active", "shadow"):
        raise HTTPException(400, "mode must be 'active' or 'shadow'")
    _MODE["current"] = mode
    if threshold is not None:
        try:
            l1_engine.set_threshold(threshold)
        except ValueError as e:
            raise HTTPException(400, str(e))
    return {"mode": _MODE["current"], "threshold": l1_engine.close_threshold}


# ── Feedback review ────────────────────────────────────────────────────────

@router.get("/feedback")
async def list_feedback(limit: int = Query(50, ge=1, le=500)):
    """List human overrides for review."""
    db: Session = SessionLocal()
    try:
        entries = db.query(FeedbackModel).order_by(FeedbackModel.created_at.desc()).limit(limit).all()
        return {
            "count": len(entries),
            "entries": [_fb_to_dict(e) for e in entries],
        }
    finally:
        db.close()


# ── Helpers ─────────────────────────────────────────────────────────────────

def _audit_to_dict(e: AuditLogModel) -> dict:
    return {
        "id": e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "alert_id": e.alert_id,
        "alert_source": e.alert_source,
        "alert_signature": e.alert_signature,
        "alert_title": e.alert_title,
        "alert_severity": e.alert_severity,
        "decision": e.decision,
        "confidence": e.confidence,
        "reason": e.reason,
        "primary_signal": e.primary_signal,
        "signals": e.signals,
        "action_taken": e.action_taken,
        "mode": e.mode,
        "overridden_at": e.overridden_at.isoformat() if e.overridden_at else None,
        "overridden_by": e.overridden_by,
        "override_reason": e.override_reason,
    }


def _wl_to_dict(e: WhitelistEntryModel) -> dict:
    return {
        "id": e.id,
        "entry_type": e.entry_type,
        "match_value": e.match_value,
        "match_field": e.match_field,
        "match_pattern": e.match_pattern,
        "name": e.name,
        "description": e.description,
        "severity_filter": e.severity_filter,
        "source_filter": e.source_filter,
        "ttl_seconds": e.ttl_seconds,
        "enabled": e.enabled,
        "hit_count": e.hit_count,
        "last_hit_at": e.last_hit_at.isoformat() if e.last_hit_at else None,
        "created_by": e.created_by,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


def _fb_to_dict(e: FeedbackModel) -> dict:
    return {
        "id": e.id,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "alert_id": e.alert_id,
        "original_decision": e.original_decision,
        "original_confidence": e.original_confidence,
        "original_reason": e.original_reason,
        "human_decision": e.human_decision,
        "human_reason": e.human_reason,
        "human_reviewer": e.human_reviewer,
        "learned": e.learned,
    }


def _get_current_mode() -> str:
    return _MODE["current"]


def ll1_uses_llm() -> bool:
    from bradlyai.services.llm_classifier import llm_classifier
    return llm_classifier.is_available()
