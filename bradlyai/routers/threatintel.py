"""Threat-intel router — IP / domain / hash lookups across providers."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.user import UserModel
from bradlyai.services.auth import require_permission
from bradlyai.services.threatintel import lookup_ip

router = APIRouter(prefix="/threatintel", tags=["Threat Intel"])


class LookupRequest(BaseModel):
    ips: Optional[List[str]] = None
    domains: Optional[List[str]] = None
    hashes: Optional[List[str]] = None
    sources: Optional[List[str]] = None


@router.post("/lookup")
def lookup(req: LookupRequest, _: UserModel = Depends(require_permission("threatintel", "read"))):
    out: Dict[str, Any] = {"ips": {}, "domains": {}, "hashes": {}}
    if req.ips:
        for ip in req.ips:
            out["ips"][ip] = lookup_ip(ip, sources=req.sources)
    if req.domains:
        for d in req.domains:
            try:
                from bradlyai.services.threatintel.virustotal import VirusTotalClient
                out["domains"][d] = VirusTotalClient().domain(d)
            except Exception as exc:
                out["domains"][d] = {"error": str(exc)}
    if req.hashes:
        for h in req.hashes:
            try:
                from bradlyai.services.threatintel.virustotal import VirusTotalClient
                out["hashes"][h] = VirusTotalClient().file(h)
            except Exception as exc:
                out["hashes"][h] = {"error": str(exc)}
    return out
