"""Identity router — user disable/enable, session revoke, password reset."""
from typing import Any, Dict

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from bradlyai.services.auth import require_permission
from bradlyai.services.identity import get_identity_client

router = APIRouter(prefix="/identity", tags=["Identity Containment"])


class UserRequest(BaseModel):
    user: str
    reason: str = ""


@router.post("/disable",
             dependencies=[Depends(require_permission("response", "execute"))])
def disable_user(req: UserRequest):
    from bradlyai.services.metrics import IDENTITY_ACTIONS
    r = get_identity_client().disable_user(req.user, req.reason)
    IDENTITY_ACTIONS.labels(provider=r.get("provider", "unknown"),
                            action="disable_user",
                            dry_run=str(r.get("dry_run", False)).lower()).inc()
    return r


@router.post("/enable",
             dependencies=[Depends(require_permission("response", "execute"))])
def enable_user(req: UserRequest):
    from bradlyai.services.metrics import IDENTITY_ACTIONS
    r = get_identity_client().enable_user(req.user)
    IDENTITY_ACTIONS.labels(provider=r.get("provider", "unknown"),
                            action="enable_user",
                            dry_run=str(r.get("dry_run", False)).lower()).inc()
    return r


@router.post("/revoke-sessions",
             dependencies=[Depends(require_permission("response", "execute"))])
def revoke_sessions(req: UserRequest):
    from bradlyai.services.metrics import IDENTITY_ACTIONS
    r = get_identity_client().revoke_sessions(req.user)
    IDENTITY_ACTIONS.labels(provider=r.get("provider", "unknown"),
                            action="revoke_sessions",
                            dry_run=str(r.get("dry_run", False)).lower()).inc()
    return r


@router.post("/reset-password",
             dependencies=[Depends(require_permission("response", "execute"))])
def reset_password(req: UserRequest):
    return get_identity_client().reset_password(req.user)


@router.get("/config",
            dependencies=[Depends(require_permission("response", "read"))])
def get_config():
    from bradlyai.config import settings
    return {
        "provider": settings.IDENTITY_PROVIDER,
        "enabled": settings.IDENTITY_ENABLED,
        "dry_run": settings.IDENTITY_DRY_RUN,
        "available_providers": ["none", "azure_ad", "okta"],
    }
