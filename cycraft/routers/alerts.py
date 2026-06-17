"""
FastAPI Router for Security Alerts & Incident Triage
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from cycraft.database import get_db
from cycraft.models.alert import AlertModel, AlertStorylineModel
from cycraft.schemas.alert import AlertResponse, TriggerAttackRequest
from cycraft.services.ai_engine import ai_engine

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    search_query: Optional[str] = Query(None, description="Search in threat titles or endpoint hostnames"),
    skip: int = Query(0, ge=0, description="Pagination skip parameter"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit parameter"),
    db: Session = Depends(get_db)
):
    """
    Retrieve automated enterprise security alerts with advanced searching and pagination
    """
    query = db.query(AlertModel)
    
    if severity and severity.upper() != "ALL":
        query = query.filter(AlertModel.severity == severity.upper())
        
    if search_query:
        query = query.filter(
            (AlertModel.title.ilike(f"%{search_query}%")) |
            (AlertModel.endpoint.ilike(f"%{search_query}%")) |
            (AlertModel.id.ilike(f"%{search_query}%"))
        )
    
    alerts = query.order_by(AlertModel.created_at.desc()).offset(skip).limit(limit).all()
    return alerts

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: str, db: Session = Depends(get_db)):
    """
    Get detailed AI autonomous storyline for a specific alert
    """
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found in active pool.")
    return alert

@router.post("/trigger-simulated-attack")
def trigger_attack(req: TriggerAttackRequest, db: Session = Depends(get_db)):
    """
    Trigger a live simulated cyber attack to observe CyCraft AI automatically detect, analyze, and remediate
    """
    simulated_scenarios = [
        ("DEV-WIN-SRV09", "45.33.12.9", "Reflective DLL Memory Injection & Credential Harvesting"),
        ("FIN-WRK-102", "192.168.20.12", "Unauthorized Lateral Movement via SMB Exploitation"),
        ("ENG-MAC-404", "192.168.15.88", "Exfiltration Attempt to Known Tor Exit Node")
    ]
    
    scen = simulated_scenarios[req.scenario] if req.scenario < len(simulated_scenarios) else simulated_scenarios[0]
    
    new_alert_data = ai_engine.analyze_anomaly(endpoint=scen[0], ip=scen[1], raw_behavior=scen[2])
    
    db_alert = AlertModel(
        id=new_alert_data["id"],
        severity=new_alert_data["severity"],
        title=new_alert_data["title"],
        endpoint=new_alert_data["endpoint"],
        ip=new_alert_data["ip"],
        timestamp=new_alert_data["timestamp"],
        mitre=new_alert_data["mitre"],
        status=new_alert_data["status"],
        ai_confidence=new_alert_data["ai_confidence"]
    )
    
    for st in new_alert_data["storyline"]:
        db_alert.storyline.append(AlertStorylineModel(time=st["time"], event=st["event"]))
        
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    
    return {
        "status": "INTERCEPTED",
        "message": f"CyCraft Multi-Model AI successfully intercepted simulated adversary scenario #{req.scenario}.",
        "alert_id": db_alert.id,
        "action_taken": "Host Bi-directionally Isolated & TGT Tokens Revoked instantly."
    }
