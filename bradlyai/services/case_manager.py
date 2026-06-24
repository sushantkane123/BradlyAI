"""Case management service — CRUD, notes, evidence, status changes, SLA tracking."""
import datetime
import secrets
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from bradlyai.models.case import CaseModel, CaseNoteModel, CaseEvidenceModel
from bradlyai.models.alert import AlertModel


# SLA mapping by priority (hours)
SLA_HOURS = {"P1": 1, "P2": 4, "P3": 24, "P4": 72, "P5": 168}


def create_case(db: Session, *, title: str, severity: str, description: Optional[str] = None,
                priority: str = "P3", assignee: Optional[str] = None,
                classification: Optional[str] = None,
                tenant_id: Optional[str] = None,
                created_by: Optional[str] = None,
                alert_id: Optional[str] = None) -> CaseModel:
    case = CaseModel(
        id=f"CASE-{secrets.token_hex(4).upper()}",
        title=title, severity=severity, description=description, priority=priority,
        status="OPEN", classification=classification, tenant_id=tenant_id,
        assignee=assignee, created_by=created_by,
        sla_due_at=datetime.datetime.now(datetime.timezone.utc) +
                    datetime.timedelta(hours=SLA_HOURS.get(priority, 24)),
    )
    db.add(case)
    db.flush()
    if alert_id:
        alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
        if alert:
            alert.case_id = case.id
            add_note(db, case.id, created_by or "system",
                     f"Case created from alert {alert.id}", note_type="system")
    db.commit()
    db.refresh(case)
    return case


def add_note(db: Session, case_id: str, author: str, note: str,
             note_type: str = "comment") -> CaseNoteModel:
    n = CaseNoteModel(case_id=case_id, author=author, note=note, note_type=note_type)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


def add_evidence(db: Session, case_id: str, evidence_type: str, value: str,
                 source: Optional[str] = None, collected_by: Optional[str] = None) -> CaseEvidenceModel:
    e = CaseEvidenceModel(case_id=case_id, evidence_type=evidence_type, value=value,
                          source=source, collected_by=collected_by,
                          chain_of_custody_json=[{
                              "actor": collected_by or "system",
                              "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                              "action": "collected",
                          }])
    db.add(e)
    db.commit()
    db.refresh(e)
    return e


def set_case_status(db: Session, case_id: str, status: str, actor: str = "system",
                    note: Optional[str] = None) -> CaseModel:
    case = db.query(CaseModel).filter(CaseModel.id == case_id).first()
    if case is None:
        raise ValueError(f"Case not found: {case_id}")
    prev = case.status
    case.status = status
    if status in ("RESOLVED", "CLOSED"):
        case.closed_at = datetime.datetime.now(datetime.timezone.utc)
    add_note(db, case_id, actor, note or f"Status: {prev} → {status}", note_type="status_change")
    db.commit()
    db.refresh(case)
    return case


def refresh_sla_breaches(db: Session) -> int:
    """Mark cases whose SLA due date has passed. Returns count updated."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cases = db.query(CaseModel).filter(
        CaseModel.status.in_(["OPEN", "IN_PROGRESS", "ESCALATED"]),
        CaseModel.sla_due_at != None,  # noqa: E711
        CaseModel.sla_due_at < now,
        CaseModel.sla_breached == 0,
    ).all()
    for c in cases:
        c.sla_breached = 1
        add_note(db, c.id, "system", f"SLA breached (due {c.sla_due_at.isoformat()})", note_type="system")
    db.commit()
    return len(cases)


def case_summary(db: Session, case_id: str) -> Dict[str, Any]:
    case = db.query(CaseModel).filter(CaseModel.id == case_id).first()
    if case is None:
        raise ValueError(f"Case not found: {case_id}")
    return {
        "id": case.id, "title": case.title, "severity": case.severity,
        "status": case.status, "priority": case.priority,
        "classification": case.classification, "assignee": case.assignee,
        "assignment_group": case.assignment_group,
        "current_playbook_id": case.current_playbook_id,
        "pending_approval_step": case.pending_approval_step,
        "external_refs": case.external_refs_json or {},
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "sla_due_at": case.sla_due_at.isoformat() if case.sla_due_at else None,
        "sla_breached": case.sla_breached,
        "notes": [{"author": n.author, "note": n.note, "type": n.note_type,
                   "at": n.created_at.isoformat() if n.created_at else None} for n in case.notes],
        "evidence": [{"type": e.evidence_type, "value": e.value, "source": e.source,
                      "at": e.created_at.isoformat() if e.created_at else None} for e in case.evidence],
        "linked_alerts": [a.id for a in case.alerts],
    }
