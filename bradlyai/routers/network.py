"""Network router — IP block/unblock + host quarantine via firewall."""
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from bradlyai.services.auth import require_permission
from bradlyai.services.network import get_network_client

router = APIRouter(prefix="/network", tags=["Network Containment"])


class BlockIpRequest(BaseModel):
    ip: str
    duration_hours: Optional[int] = None
    reason: str = ""


class IpRequest(BaseModel):
    ip: str


class HostRequest(BaseModel):
    host: str


@router.post("/block-ip",
             dependencies=[Depends(require_permission("response", "execute"))])
def block_ip(req: BlockIpRequest):
    from bradlyai.services.metrics import NETWORK_ACTIONS
    r = get_network_client().block_ip(req.ip, req.duration_hours, req.reason)
    NETWORK_ACTIONS.labels(provider=r.get("provider", "unknown"),
                           action="block_ip",
                           dry_run=str(r.get("dry_run", False)).lower()).inc()
    return r


@router.post("/unblock-ip",
             dependencies=[Depends(require_permission("response", "execute"))])
def unblock_ip(req: IpRequest):
    from bradlyai.services.metrics import NETWORK_ACTIONS
    r = get_network_client().unblock_ip(req.ip)
    NETWORK_ACTIONS.labels(provider=r.get("provider", "unknown"),
                           action="unblock_ip",
                           dry_run=str(r.get("dry_run", False)).lower()).inc()
    return r


@router.post("/quarantine-host",
             dependencies=[Depends(require_permission("response", "execute"))])
def quarantine_host(req: HostRequest):
    from bradlyai.services.metrics import NETWORK_ACTIONS
    r = get_network_client().quarantine_host(req.host)
    NETWORK_ACTIONS.labels(provider=r.get("provider", "unknown"),
                           action="quarantine_host",
                           dry_run=str(r.get("dry_run", False)).lower()).inc()
    return r


@router.get("/config",
            dependencies=[Depends(require_permission("response", "read"))])
def get_config():
    from bradlyai.config import settings
    return {
        "provider": settings.NETWORK_PROVIDER,
        "enabled": settings.NETWORK_ENABLED,
        "dry_run": settings.NETWORK_DRY_RUN,
        "available_providers": ["none", "paloalto", "fortinet", "cisco_asa", "checkpoint"],
    }
