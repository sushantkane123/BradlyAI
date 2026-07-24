"""Authenticated API for evidence-first human-like SOC investigations."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.alert import AlertModel
from bradlyai.models.investigation import InvestigationModel
from bradlyai.services.auth import get_current_user, require_permission
from bradlyai.services.investigation_agent import run_investigation, to_dict

router = APIRouter(prefix="/agent", tags=["SOC Investigation Agent"])


def _get_tenant_alert(db: Session, alert_id: str, tenant_id: str | None) -> AlertModel:
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if tenant_id and alert.tenant_id and alert.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts/{alert_id}/investigate", dependencies=[Depends(require_permission("alerts", "read"))])
def investigate_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, Any]:
    """Run an evidence-first investigation. This endpoint never contains or closes assets."""
    alert = _get_tenant_alert(db, alert_id, user.tenant_id)
    investigation = run_investigation(db, alert)
    return to_dict(investigation)


@router.get("/alerts/{alert_id}/investigations", dependencies=[Depends(require_permission("alerts", "read"))])
def list_alert_investigations(
    alert_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, Any]:
    _get_tenant_alert(db, alert_id, user.tenant_id)
    query = db.query(InvestigationModel).filter(InvestigationModel.alert_id == alert_id)
    if user.tenant_id:
        query = query.filter(InvestigationModel.tenant_id == user.tenant_id)
    rows = query.order_by(InvestigationModel.created_at.desc()).limit(limit).all()
    return {"count": len(rows), "investigations": [to_dict(row) for row in rows]}


@router.get("/investigations/{investigation_id}", dependencies=[Depends(require_permission("alerts", "read"))])
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
) -> dict[str, Any]:
    query = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id)
    if user.tenant_id:
        query = query.filter(InvestigationModel.tenant_id == user.tenant_id)
    item = query.first()
    if item is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return to_dict(item)
