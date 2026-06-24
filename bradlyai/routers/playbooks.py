"""Playbooks router — list, trigger, resume."""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.playbook import PlaybookModel, PlaybookRunModel
from bradlyai.models.user import UserModel
from bradlyai.services.auth import require_permission, get_current_user
from bradlyai.services.playbook_engine import run_playbook, resume_playbook, BUILTIN_PLAYBOOKS

logger = logging.getLogger("bradlyai.playbooks")
router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


class TriggerRequest(BaseModel):
    playbook_id: str
    alert: Optional[Dict[str, Any]] = None
    case_id: Optional[str] = None


class ResumeRequest(BaseModel):
    approved: bool


def _to_dict_run(r: PlaybookRunModel) -> Dict[str, Any]:
    return {
        "id": r.id, "playbook_id": r.playbook_id, "case_id": r.case_id,
        "alert_id": r.alert_id, "status": r.status, "current_step": r.current_step,
        "pending_approval_step": r.pending_approval_step,
        "state": r.state_json, "history": r.history_json,
        "error": r.error,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "triggered_by": r.triggered_by, "tenant_id": r.tenant_id,
    }


@router.get("")
def list_playbooks(db: Session = Depends(get_db),
                   _: UserModel = Depends(require_permission("playbooks", "read"))):
    return [{
        "id": p.id, "name": p.name, "description": p.description,
        "trigger": p.trigger, "severity_filter": p.severity_filter,
        "is_builtin": p.is_builtin, "enabled": p.enabled,
        "steps": (p.steps_json or {}).get("steps", []) if isinstance(p.steps_json, dict) else (p.steps_json or []),
    } for p in db.query(PlaybookModel).all()]


@router.post("/trigger")
def trigger(req: TriggerRequest, db: Session = Depends(get_db),
            user: UserModel = Depends(require_permission("playbooks", "run"))):
    run = run_playbook(db, req.playbook_id, alert=req.alert, case_id=req.case_id,
                       triggered_by=user.username, tenant_id=user.tenant_id)
    from bradlyai.services.metrics import PLAYBOOK_RUNS
    PLAYBOOK_RUNS.labels(playbook_id=req.playbook_id, status=run.status).inc()
    return _to_dict_run(run)


@router.post("/runs/{run_id}/resume")
def resume(run_id: str, req: ResumeRequest, db: Session = Depends(get_db),
           user: UserModel = Depends(require_permission("playbooks", "approve"))):
    run = resume_playbook(db, run_id, req.approved, actor=user.username)
    from bradlyai.services.metrics import PLAYBOOK_RUNS
    PLAYBOOK_RUNS.labels(playbook_id=run.playbook_id, status=run.status).inc()
    return _to_dict_run(run)


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db),
            _: UserModel = Depends(require_permission("playbooks", "read"))):
    run = db.query(PlaybookRunModel).filter(PlaybookRunModel.id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return _to_dict_run(run)


@router.get("/runs")
def list_runs(status: Optional[str] = None, limit: int = 50,
              db: Session = Depends(get_db),
              _: UserModel = Depends(require_permission("playbooks", "read"))):
    q = db.query(PlaybookRunModel)
    if status:
        q = q.filter(PlaybookRunModel.status == status)
    return [_to_dict_run(r) for r in q.order_by(PlaybookRunModel.started_at.desc()).limit(limit).all()]
