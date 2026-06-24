"""EDR router — host containment, file quarantine, process query."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from bradlyai.services.auth import require_permission
from bradlyai.services.edr import get_edr_client

router = APIRouter(prefix="/edr", tags=["EDR"])


class HostActionRequest(BaseModel):
    host_id: str
    reason: str = ""


class FileActionRequest(BaseModel):
    sha256: str
    reason: str = ""


class ProcessQueryRequest(BaseModel):
    host_id: str
    since: Optional[str] = None


@router.post("/hosts/isolate",
             dependencies=[Depends(require_permission("response", "execute"))])
def isolate_host(req: HostActionRequest):
    from bradlyai.services.metrics import EDR_ACTIONS
    result = get_edr_client().isolate_host(req.host_id, req.reason)
    EDR_ACTIONS.labels(provider=result.get("provider", "unknown"),
                       action="isolate_host",
                       dry_run=str(result.get("dry_run", False)).lower()).inc()
    return result


@router.post("/hosts/release",
             dependencies=[Depends(require_permission("response", "execute"))])
def release_host(req: HostActionRequest):
    from bradlyai.services.metrics import EDR_ACTIONS
    result = get_edr_client().release_host(req.host_id)
    EDR_ACTIONS.labels(provider=result.get("provider", "unknown"),
                       action="release_host",
                       dry_run=str(result.get("dry_run", False)).lower()).inc()
    return result


@router.post("/files/quarantine",
             dependencies=[Depends(require_permission("response", "execute"))])
def quarantine_file(req: FileActionRequest):
    from bradlyai.services.metrics import EDR_ACTIONS
    result = get_edr_client().quarantine_file(req.sha256, req.reason)
    EDR_ACTIONS.labels(provider=result.get("provider", "unknown"),
                       action="quarantine_file",
                       dry_run=str(result.get("dry_run", False)).lower()).inc()
    return result


@router.post("/processes",
             dependencies=[Depends(require_permission("response", "read"))])
def query_processes(req: ProcessQueryRequest):
    return get_edr_client().get_processes(req.host_id, req.since)


@router.get("/config")
def get_config(_=Depends(require_permission("response", "read"))):
    from bradlyai.config import settings
    return {
        "provider": settings.EDR_PROVIDER,
        "enabled": settings.EDR_ENABLED,
        "dry_run": settings.EDR_DRY_RUN,
        "available_providers": ["none", "crowdstrike", "defender", "sentinelone", "carbonblack"],
    }
