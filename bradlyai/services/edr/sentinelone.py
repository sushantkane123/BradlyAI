"""SentinelOne integration."""
import logging
import time
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.edr import BaseEDR

logger = logging.getLogger("bradlyai.edr.sentinelone")


class SentinelOneEDR(BaseEDR):
    provider = "sentinelone"
    _TOKEN: Dict[str, Any] = {"value": None, "expires_at": 0}

    def _get_token(self) -> str:
        now = time.time()
        if self._TOKEN["value"] and self._TOKEN["expires_at"] > now + 60:
            return self._TOKEN["value"]
        url = f"{settings.SENTINELONE_BASE_URL}/web/api/v2.1/users/login/api-token"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, json={"data": {"apiToken": settings.SENTINELONE_API_TOKEN}})
            r.raise_for_status()
            data = r.json().get("data", {})
        self._TOKEN = {"value": data.get("token"), "expires_at": now + 3600}
        return self._TOKEN["value"]

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"ApiToken {self._get_token()}",
                "Content-Type": "application/json"}

    def _agent_id_for_host(self, hostname: str) -> str:
        url = f"{settings.SENTINELONE_BASE_URL}/web/api/v2.1/agents"
        with httpx.Client(timeout=15) as c:
            r = c.get(url, headers=self._headers(), params={"computerName": hostname})
            r.raise_for_status()
            agents = r.json().get("data", [])
        return agents[0]["id"] if agents else hostname

    def _isolate_host(self, host_id: str, reason: str) -> Dict[str, Any]:
        agent_id = self._agent_id_for_host(host_id)
        url = f"{settings.SENTINELONE_BASE_URL}/web/api/v2.1/agents/{agent_id}/actions/disconnect"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(), json={"data": {"reason": reason or "BradlyAI isolation"}})
            return {"status": r.status_code, "agent_id": agent_id, "response": r.json()}

    def _release_host(self, host_id: str) -> Dict[str, Any]:
        agent_id = self._agent_id_for_host(host_id)
        url = f"{settings.SENTINELONE_BASE_URL}/web/api/v2.1/agents/{agent_id}/actions/connect"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(), json={"data": {}})
            return {"status": r.status_code, "agent_id": agent_id, "response": r.json()}

    def _quarantine_file(self, sha256: str, reason: str) -> Dict[str, Any]:
        # SentinelOne uses threat policies via /threats endpoint.
        url = f"{settings.SENTINELONE_BASE_URL}/web/api/v2.1/threats"
        body = {"data": {"sha256": sha256, "classification": "MALICIOUS",
                         "classificationSource": "BradlyAI",
                         "action": "Quarantine"}}
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(), json=body)
            return {"status": r.status_code, "sha256": sha256, "response": r.json()}
