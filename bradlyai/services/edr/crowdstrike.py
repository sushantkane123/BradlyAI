"""CrowdStrike Falcon integration — host containment + file quarantine."""
import logging
import time
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.edr import BaseEDR

logger = logging.getLogger("bradlyai.edr.crowdstrike")


class CrowdStrikeEDR(BaseEDR):
    provider = "crowdstrike"
    _TOKEN: Dict[str, Any] = {"value": None, "expires_at": 0}

    def _get_token(self) -> str:
        now = time.time()
        if self._TOKEN["value"] and self._TOKEN["expires_at"] > now + 60:
            return self._TOKEN["value"]
        url = f"{settings.CROWDSTRIKE_BASE_URL}/oauth2/token"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, data={"client_id": settings.CROWDSTRIKE_CLIENT_ID,
                                  "client_secret": settings.CROWDSTRIKE_CLIENT_SECRET})
            r.raise_for_status()
            data = r.json()
        self._TOKEN = {"value": data["access_token"], "expires_at": now + data.get("expires_in", 1800)}
        return self._TOKEN["value"]

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json"}

    def _device_id_for_host(self, hostname: str) -> str:
        """Resolve hostname → CrowdStrike device ID via the Hosts API."""
        url = f"{settings.CROWDSTRIKE_BASE_URL}/devices/queries/devices/v1"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(),
                       json={"filter": f"hostname:'{hostname}'", "limit": 1})
            r.raise_for_status()
            ids = r.json().get("resources", [])
        return ids[0] if ids else hostname     # fall back to using hostname directly

    def _isolate_host(self, host_id: str, reason: str) -> Dict[str, Any]:
        device_id = self._device_id_for_host(host_id)
        url = f"{settings.CROWDSTRIKE_BASE_URL}/devices/entities/devices-actions/v2?action_name=contain"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(), json={"ids": [device_id]})
            return {"status": r.status_code, "device_id": device_id, "response": r.json()}

    def _release_host(self, host_id: str) -> Dict[str, Any]:
        device_id = self._device_id_for_host(host_id)
        url = f"{settings.CROWDSTRIKE_BASE_URL}/devices/entities/devices-actions/v2?action_name=lift_containment"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(), json={"ids": [device_id]})
            return {"status": r.status_code, "device_id": device_id, "response": r.json()}

    def _quarantine_file(self, sha256: str, reason: str) -> Dict[str, Any]:
        url = f"{settings.CROWDSTRIKE_BASE_URL}/iocs/entities/iocs/v1"
        body = {"type": "sha256", "value": sha256,
                "action": "prevent", "platforms": ["windows", "mac", "linux"],
                "description": reason or "Quarantined by BradlyAI"}
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(), json=body)
            return {"status": r.status_code, "sha256": sha256, "response": r.json()}

    def get_processes(self, host_id: str, since: str = None) -> Dict[str, Any]:
        device_id = self._device_id_for_host(host_id)
        url = f"{settings.CROWDSTRIKE_BASE_URL}/processes/queries/processes/v1"
        body = {"filter": f"device_id:'{device_id}'", "limit": 100}
        if since:
            body["filter"] += f"+start_time_raw:>='{since}'"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(), json=body)
            return {"status": r.status_code, "processes": r.json().get("resources", [])}
