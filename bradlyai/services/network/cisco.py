"""Cisco ASA / Firepower integration (REST API)."""
import logging
import base64
from typing import Any, Dict, Optional

import httpx

from bradlyai.config import settings
from bradlyai.services.network import BaseNetwork

logger = logging.getLogger("bradlyai.network.cisco")


class CiscoAsaNetwork(BaseNetwork):
    provider = "cisco_asa"

    def _headers(self) -> Dict[str, str]:
        token = base64.b64encode(
            f"{settings.CISCO_ASA_USERNAME}:{settings.CISCO_ASA_PASSWORD}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}",
                "Content-Type": "application/json"}

    def _block_ip(self, ip: str, duration_hours: Optional[int], reason: str) -> Dict[str, Any]:
        # Cisco ASA ACL management — add deny entry
        url = f"{settings.CISCO_ASA_BASE_URL}/api/access/acl"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(url, headers=self._headers(), json={
                "name": "bradlyai_denylist",
                "rules": [{
                    "action": "deny", "src": "any", "dst": ip,
                    "service": "any", "comment": reason or "BradlyAI block",
                }],
            })
            return {"status": r.status_code, "ip": ip, "response": r.text}

    def _unblock_ip(self, ip: str) -> Dict[str, Any]:
        url = f"{settings.CISCO_ASA_BASE_URL}/api/access/acl/bradlyai_denylist/rules"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.delete(url, headers=self._headers(),
                         params={"dst": ip})
            return {"status": r.status_code, "ip": ip}

    def _quarantine_host(self, target: str) -> Dict[str, Any]:
        return {"status": "manual", "target": target,
                "note": "Move host to quarantine VLAN via Cisco ISE"}
