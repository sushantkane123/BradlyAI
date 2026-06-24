"""Metrics router — Prometheus /metrics endpoint + custom counters."""
from fastapi import APIRouter, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.orm import Session
from fastapi import Depends

from bradlyai.config import settings
from bradlyai.database import get_db
from bradlyai.models.case import CaseModel
from bradlyai.services.metrics import OPEN_CASES

router = APIRouter(tags=["Observability"])


@router.get("/metrics")
def prometheus_metrics(db: Session = Depends(get_db)):
    """Refresh open-cases gauge then return Prometheus exposition."""
    # Refresh gauge values
    from sqlalchemy import func
    counts = (db.query(CaseModel.priority, func.count(CaseModel.id))
              .filter(CaseModel.status.in_(["OPEN", "IN_PROGRESS", "ESCALATED"]))
              .group_by(CaseModel.priority).all())
    for priority in ["P1", "P2", "P3", "P4", "P5"]:
        OPEN_CASES.labels(priority=priority).set(0)
    for priority, count in counts:
        OPEN_CASES.labels(priority=priority or "P3").set(count)

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@router.get("/health/live")
def liveness():
    return {"status": "alive"}


@router.get("/health/ready")
def readiness(db: Session = Depends(get_db)):
    from sqlalchemy import text
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as exc:
        return {"status": "not_ready", "error": str(exc)}
