"""BradlyAI Guided Remediation APIRouter (SOAR Endpoints)"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from bradlyai.database import get_db
from bradlyai.services.remediation_engine import remediation_engine

logger = logging.getLogger("bradlyai.remediation_router")

router = APIRouter(prefix="/remediation", tags=["Guided Remediation SOAR"])

class RemediationRequest(BaseModel):
    alert_id: str
    action: str  # isolate_host / revoke_user / block_ip
    target: str  # host name, IP address, or username
    reviewer: str

class RemediationResponse(BaseModel):
    status: str
    action: str
    target: str
    status_text: str
    reviewer: str
    timestamp: str
    execution_logs: List[str]

@router.post("/execute", response_model=RemediationResponse)
async def execute_remediation(req: RemediationRequest, db: Session = Depends(get_db)):
    """Authorize and execute active containment commands against integrated tools."""
    try:
        result = remediation_engine.execute_action(
            db=db,
            action_type=req.action,
            target_entity=req.target,
            alert_id=req.alert_id,
            reviewer=req.reviewer
        )
        return result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as e:
        logger.error(f"Remediation execution failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to execute containment request."
        )
