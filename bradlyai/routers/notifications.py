"""Notifications router — unified API to test + send notifications."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.notification_log import NotificationLogModel
from bradlyai.models.user import UserModel
from bradlyai.services.auth import require_permission
from bradlyai.services.notifications import notify, escalate_to_l2

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class NotifyRequest(BaseModel):
    channel: str             # slack | teams | pagerduty | email | webhook
    message: Optional[str] = None
    subject: Optional[str] = None
    to: Optional[str] = None
    channel_name: Optional[str] = None
    severity: Optional[str] = None
    summary: Optional[str] = None
    url: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None


class EscalateRequest(BaseModel):
    alert: Dict[str, Any]
    reason: str
    channels: Optional[List[str]] = None


@router.post("/send")
def send(req: NotifyRequest, db: Session = Depends(get_db),
         user: UserModel = Depends(require_permission("notifications", "write"))):
    result = notify(req.channel, message=req.message, subject=req.subject, to=req.to,
                    channel=req.channel_name, severity=req.severity, summary=req.summary,
                    url=req.url, payload=req.payload)
    db.add(NotificationLogModel(
        channel=req.channel, target=req.to or req.channel_name, subject=req.subject,
        body=req.message, success=str(result.get("success", False)).lower(),
        detail=result.get("detail", ""), triggered_by=user.username, tenant_id=user.tenant_id,
        payload_json=result.get("extra", {}),
    ))
    db.commit()
    return result


@router.post("/escalate")
def escalate(req: EscalateRequest, db: Session = Depends(get_db),
             user: UserModel = Depends(require_permission("notifications", "write"))):
    res = escalate_to_l2(req.alert, req.reason, channels=req.channels)
    for ch, result in res.get("results", {}).items():
        db.add(NotificationLogModel(
            channel=ch, target=req.alert.get("id"), subject=res["summary"],
            body=req.reason, success=str(result.get("success", False)).lower(),
            detail=result.get("detail", ""), triggered_by=user.username, tenant_id=user.tenant_id,
        ))
    db.commit()
    return res


@router.get("/log")
def list_log(limit: int = 100, channel: Optional[str] = None,
             db: Session = Depends(get_db),
             user: UserModel = Depends(require_permission("notifications", "read"))):
    q = db.query(NotificationLogModel)
    if channel:
        q = q.filter(NotificationLogModel.channel == channel)
    rows = q.order_by(NotificationLogModel.created_at.desc()).limit(limit).all()
    return [{
        "channel": r.channel, "target": r.target, "subject": r.subject, "body": r.body,
        "success": r.success == "true", "detail": r.detail, "at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]
