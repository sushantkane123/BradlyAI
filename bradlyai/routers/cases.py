"""Cases router — CRUD + notes + evidence + status changes."""
import datetime
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.user import UserModel
from bradlyai.models.case import CaseModel
from bradlyai.services.auth import require_permission
from bradlyai.services.case_manager import (
    add_note, add_evidence, create_case, set_case_status, case_summary,
    refresh_sla_breaches,
)

logger = logging.getLogger("bradlyai.cases")
router = APIRouter(prefix="/cases", tags=["Cases"])


class CreateCaseRequest(BaseModel):
    title: str
    severity: str
    description: Optional[str] = None
    priority: str = "P3"
    assignee: Optional[str] = None
    classification: Optional[str] = None
    alert_id: Optional[str] = None


class NoteRequest(BaseModel):
    note: str
    note_type: str = "comment"


class StatusRequest(BaseModel):
    status: str
    note: Optional[str] = None


class EvidenceRequest(BaseModel):
    evidence_type: str
    value: str
    source: Optional[str] = None


class CaseResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    priority: str
    assignee: Optional[str]
    sla_due_at: Optional[datetime.datetime]
    sla_breached: int
    created_at: datetime.datetime
    closed_at: Optional[datetime.datetime]


def _to_dict(c: CaseModel) -> Dict[str, Any]:
    return {
        "id": c.id, "title": c.title, "severity": c.severity,
        "status": c.status, "priority": c.priority,
        "assignee": c.assignee, "assignment_group": c.assignment_group,
        "classification": c.classification, "tenant_id": c.tenant_id,
        "current_playbook_id": c.current_playbook_id,
        "pending_approval_step": c.pending_approval_step,
        "external_refs": c.external_refs_json or {},
        "sla_due_at": c.sla_due_at.isoformat() if c.sla_due_at else None,
        "sla_breached": c.sla_breached,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        "closed_at": c.closed_at.isoformat() if c.closed_at else None,
        "created_by": c.created_by,
    }


@router.post("", status_code=201,
             dependencies=[Depends(require_permission("cases", "write"))])
def create_case_endpoint(req: CreateCaseRequest, db: Session = Depends(get_db),
                         user: UserModel = Depends(__import__("bradlyai").services.auth.get_current_user if False else __import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    case = create_case(db, title=req.title, severity=req.severity, description=req.description,
                       priority=req.priority, assignee=req.assignee,
                       classification=req.classification, tenant_id=user.tenant_id,
                       created_by=user.username, alert_id=req.alert_id)
    from bradlyai.services.metrics import CASES_CREATED
    CASES_CREATED.labels(severity=req.severity).inc()
    return _to_dict(case)


@router.get("")
def list_cases(status: Optional[str] = None, priority: Optional[str] = None,
               severity: Optional[str] = None, limit: int = Query(100, le=500),
               db: Session = Depends(get_db),
               user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    q = db.query(CaseModel)
    if user.tenant_id:
        q = q.filter(CaseModel.tenant_id == user.tenant_id)
    if status:
        q = q.filter(CaseModel.status == status)
    if priority:
        q = q.filter(CaseModel.priority == priority)
    if severity:
        q = q.filter(CaseModel.severity == severity)
    return [_to_dict(c) for c in q.order_by(CaseModel.created_at.desc()).limit(limit).all()]


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db),
             _: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    return case_summary(db, case_id)


@router.post("/{case_id}/notes",
             dependencies=[Depends(require_permission("cases", "write"))])
def add_note_endpoint(case_id: str, req: NoteRequest, db: Session = Depends(get_db),
                      user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    n = add_note(db, case_id, user.username, req.note, req.note_type)
    return {"id": n.id, "author": n.author, "note": n.note,
            "type": n.note_type, "created_at": n.created_at}


@router.post("/{case_id}/evidence",
             dependencies=[Depends(require_permission("cases", "write"))])
def add_evidence_endpoint(case_id: str, req: EvidenceRequest, db: Session = Depends(get_db),
                          user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    e = add_evidence(db, case_id, req.evidence_type, req.value, source=req.source,
                     collected_by=user.username)
    return {"id": e.id, "type": e.evidence_type, "value": e.value, "source": e.source}


@router.post("/{case_id}/status",
             dependencies=[Depends(require_permission("cases", "write"))])
def set_status_endpoint(case_id: str, req: StatusRequest, db: Session = Depends(get_db),
                        user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    case = set_case_status(db, case_id, req.status, actor=user.username, note=req.note)
    return _to_dict(case)


@router.post("/refresh-sla",
             dependencies=[Depends(require_permission("cases", "write"))])
def refresh_sla(db: Session = Depends(get_db)):
    return {"breached_count": refresh_sla_breaches(db)}
