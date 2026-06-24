"""Check Point firewall integration."""
import logging
import time
from typing import Any, Dict, Optional

import httpx

from bradlyai.config import settings
from bradlyai.services.network import BaseNetwork

logger = logging.getLogger("bradlyai.network.checkpoint")


class CheckPointNetwork(BaseNetwork):
    provider = "checkpoint"
    _SID: Dict[str, Any] = {"value": None, "expires_at": 0}

    def _login(self) -> str:
        now = time.time()
        if self._SID["value"] and self._SID["expires_at"] > now + 60:
            return self._SID["value"]
        url = f"{settings.CHECKPOINT_BASE_URL}/web_api/login"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(url, json={"user": settings.CHECKPOINT_USERNAME,
                                  "password": settings.CHECKPOINT_PASSWORD})
            r.raise_for_status()
            sid = r.json().get("sid")
        self._SID = {"value": sid, "expires_at": now + 600}
        return sid

    def _headers(self) -> Dict[str, str]:
        return {"X-chkp-sid": self._login(), "Content-Type": "application/json"}

    def _block_ip(self, ip: str, duration_hours: Optional[int], reason: str) -> Dict[str, Any]:
        name = f"bradlyai_block_{ip.replace('.', '_')}"
        url = f"{settings.CHECKPOINT_BASE_URL}/web_api/add-host"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(url, headers=self._headers(),
                       json={"name": name, "ip-address": ip,
                             "comments": reason or "BradlyAI block"})
            return {"status": r.status_code, "ip": ip, "response": r.json()}

    def _unblock_ip(self, ip: str) -> Dict[str, Any]:
        name = f"bradlyai_block_{ip.replace('.', '_')}"
        url = f"{settings.CHECKPOINT_BASE_URL}/web_api/delete-host"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(url, headers=self._headers(), json={"name": name})
            return {"status": r.status_code, "ip": ip}

    def _quarantine_host(self, target: str) -> Dict[str, Any]:
        return {"status": "manual", "target": target,
                "note": "Quarantine via Check Point Identity Awareness"}
