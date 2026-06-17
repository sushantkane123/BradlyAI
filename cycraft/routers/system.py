"""
FastAPI Router for System Settings, API Keys, and Database Control
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from cycraft.config import settings
from cycraft.database import get_db
from cycraft.models.alert import AlertModel, AlertStorylineModel

router = APIRouter(prefix="/system", tags=["System & Settings"])

class SystemConfigUpdate(BaseModel):
    openai_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    auto_containment_threshold: Optional[float] = None
    live_simulation_active: Optional[bool] = None

@router.get("/config")
def get_system_config():
    """
    Get active application configurations and AI integration status
    """
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "openai_key_configured": bool(settings.OPENAI_API_KEY),
        "groq_key_configured": bool(settings.GROQ_API_KEY),
        "auto_containment_threshold": settings.AUTO_CONTAINMENT_THRESHOLD,
        "live_simulation_active": settings.LIVE_SIMULATION_WORKER_ACTIVE,
        "database_url": settings.DATABASE_URL
    }

@router.post("/config")
def update_system_config(req: SystemConfigUpdate):
    """
    Dynamically update API keys and driverless SOC thresholds
    """
    if req.openai_api_key is not None:
        settings.OPENAI_API_KEY = req.openai_api_key.strip() if req.openai_api_key.strip() else None
        
    if req.groq_api_key is not None:
        settings.GROQ_API_KEY = req.groq_api_key.strip() if req.groq_api_key.strip() else None
        
    if req.auto_containment_threshold is not None:
        settings.AUTO_CONTAINMENT_THRESHOLD = req.auto_containment_threshold
        
    if req.live_simulation_active is not None:
        settings.LIVE_SIMULATION_WORKER_ACTIVE = req.live_simulation_active
        
    return {
        "status": "UPDATED",
        "message": "CyCraft Advanced System Configuration successfully updated.",
        "config": get_system_config()
    }

@router.post("/reset-database")
def reset_siem_database(db: Session = Depends(get_db)):
    """
    Clear all simulated active security alerts and restore pristine initial database seed
    """
    db.query(AlertModel).delete()
    db.commit()
    
    return {
        "status": "RESET",
        "message": "Live SIEM Alert Database successfully cleared. Initial state restored."
    }
