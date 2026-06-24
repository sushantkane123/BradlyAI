"""Reports router — KPI / compliance reports in JSON / CSV / PDF."""
from typing import Optional

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.user import UserModel
from bradlyai.services.auth import require_permission
from bradlyai.services.reports import (
    audit_log_csv, nist_800_61_report, render_kpi_pdf, soc2_evidence_pack,
    soc_kpis,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/kpis",
            dependencies=[Depends(require_permission("reports", "read"))])
def kpis(since_hours: int = Query(24, le=8760),
         db: Session = Depends(get_db),
         user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    return soc_kpis(db, since_hours=since_hours, tenant_id=user.tenant_id)


@router.get("/audit.csv",
            dependencies=[Depends(require_permission("reports", "read"))])
def audit_csv(since_hours: int = Query(168, le=8760),
              db: Session = Depends(get_db),
              user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    csv_text = audit_log_csv(db, since_hours=since_hours, tenant_id=user.tenant_id)
    return Response(content=csv_text, media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=bradlyai_audit.csv"})


@router.get("/nist-800-61",
            dependencies=[Depends(require_permission("reports", "read"))])
def nist(since_hours: int = Query(168, le=8760),
         db: Session = Depends(get_db),
         user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    return nist_800_61_report(db, since_hours=since_hours, tenant_id=user.tenant_id)


@router.get("/soc2",
            dependencies=[Depends(require_permission("reports", "read"))])
def soc2(since_hours: int = Query(2160, le=8760),
         db: Session = Depends(get_db),
         user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    return soc2_evidence_pack(db, since_hours=since_hours, tenant_id=user.tenant_id)


@router.get("/kpis.pdf",
            dependencies=[Depends(require_permission("reports", "read"))])
def kpis_pdf(since_hours: int = Query(168, le=8760),
             db: Session = Depends(get_db),
             user: UserModel = Depends(__import__("bradlyai.services.auth", fromlist=["get_current_user"]).get_current_user)):
    kpis_data = soc_kpis(db, since_hours=since_hours, tenant_id=user.tenant_id)
    pdf_bytes = render_kpi_pdf(kpis_data, framework="SOC KPIs")
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=bradlyai_kpis.pdf"})
