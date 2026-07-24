"""FastAPI Router for System Settings, API Keys, and Database Control"""
import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional

from bradlyai.config import settings
from bradlyai.database import get_db
from bradlyai.models.alert import AlertModel
from bradlyai.services.auth import require_permission

logger = logging.getLogger("bradlyai.system")
router = APIRouter(prefix="/system", tags=["System & Settings"])


class SystemConfigUpdate(BaseModel):
    openai_api_key: Optional[str] = Field(None, max_length=200)
    groq_api_key: Optional[str] = Field(None, max_length=200)
    auto_containment_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    live_simulation_active: Optional[bool] = None


@router.get("/config", dependencies=[Depends(require_permission("settings", "read"))])
def get_system_config():
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "openai_key_configured": bool(settings.OPENAI_API_KEY),
        "groq_key_configured": bool(settings.GROQ_API_KEY),
        "auto_containment_threshold": settings.AUTO_CONTAINMENT_THRESHOLD,
        "live_simulation_active": settings.LIVE_SIMULATION_WORKER_ACTIVE,
        "demo_data_enabled": settings.DEMO_DATA_ENABLED,
        "ingestion_default_mode": settings.INGESTION_DEFAULT_MODE,
        # Do not expose database credentials or connection strings through the API.
        "database_driver": settings.DATABASE_URL.split(":", 1)[0],
        "llm_provider": settings.LLM_PROVIDER,
        "rate_limit_enabled": settings.RATE_LIMIT_ENABLED,
    }


@router.post("/config", dependencies=[Depends(require_permission("settings", "write"))])
def update_system_config(req: SystemConfigUpdate):
    if req.openai_api_key is not None:
        settings.OPENAI_API_KEY = req.openai_api_key.strip() if req.openai_api_key.strip() else None
    if req.groq_api_key is not None:
        settings.GROQ_API_KEY = req.groq_api_key.strip() if req.groq_api_key.strip() else None
    if req.auto_containment_threshold is not None:
        settings.AUTO_CONTAINMENT_THRESHOLD = req.auto_containment_threshold
    if req.live_simulation_active is not None:
        settings.LIVE_SIMULATION_WORKER_ACTIVE = req.live_simulation_active
    logger.info("System configuration updated.")
    return {
        "status": "UPDATED",
        "message": "BradlyAI Advanced System Configuration successfully updated.",
        "config": get_system_config(),
    }


@router.post("/reset-database", dependencies=[Depends(require_permission("settings", "write"))])
def reset_siem_database(db: Session = Depends(get_db)):
    """Clear all alerts and immediately re-seed the database."""
    from bradlyai.models.alert import AlertStorylineModel
    from bradlyai.models.asset import AssetModel, AssetFindingModel
    from bradlyai.main import seed_database

    count = db.query(AlertModel).count()
    db.query(AlertStorylineModel).delete()
    db.query(AlertModel).delete()
    db.commit()

    logger.warning(f"Database reset — {count} alerts purged, re-seeding.")
    seed_database()

    new_count = db.query(AlertModel).count()
    return {
        "status": "RESET",
        "message": f"Live SIEM Alert Database cleared ({count} alerts removed) and re-seeded with {new_count} default alerts.",
        "alerts_removed": count,
        "alerts_re_seeded": new_count,
    }
