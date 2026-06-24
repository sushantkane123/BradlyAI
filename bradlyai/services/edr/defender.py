"""Microsoft Defender for Endpoint integration."""
import logging
import time
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.edr import BaseEDR

logger = logging.getLogger("bradlyai.edr.defender")


class DefenderEDR(BaseEDR):
    provider = "defender"
    _TOKEN: Dict[str, Any] = {"value": None, "expires_at": 0}

    def _get_token(self) -> str:
        now = time.time()
        if self._TOKEN["value"] and self._TOKEN["expires_at"] > now + 60:
            return self._TOKEN["value"]
        url = (f"https://login.microsoftonline.com/{settings.DEFENDER_TENANT_ID}/oauth2/v2.0/token")
        with httpx.Client(timeout=15) as c:
            r = c.post(url, data={
                "client_id": settings.DEFENDER_CLIENT_ID,
                "client_secret": settings.DEFENDER_CLIENT_SECRET,
                "grant_type": "client_credentials",
                "scope": "https://api.securitycenter.microsoft.com/.default",
            })
            r.raise_for_status()
            data = r.json()
        self._TOKEN = {"value": data["access_token"], "expires_at": now + data.get("expires_in", 3600)}
        return self._TOKEN["value"]

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json"}

    def _machine_id_for_host(self, hostname: str) -> str:
        url = "https://api.securitycenter.microsoft.com/api/machines"
        with httpx.Client(timeout=15) as c:
            r = c.get(url, headers=self._headers(),
                      params={"$filter": f"contains(computerDnsName,'{hostname}')"})
            r.raise_for_status()
            machines = r.json().get("value", [])
        return machines[0]["id"] if machines else hostname

    def _isolate_host(self, host_id: str, reason: str) -> Dict[str, Any]:
        machine_id = self._machine_id_for_host(host_id)
        url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(),
                       json={"Comment": reason or "Isolated by BradlyAI", "IsolationType": "Full"})
            return {"status": r.status_code, "machine_id": machine_id, "response": r.text}

    def _release_host(self, host_id: str) -> Dict[str, Any]:
        machine_id = self._machine_id_for_host(host_id)
        url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/unisolate"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(),
                       json={"Comment": "Released by BradlyAI"})
            return {"status": r.status_code, "machine_id": machine_id, "response": r.text}

    def _quarantine_file(self, sha256: str, reason: str) -> Dict[str, Any]:
        url = "https://api.securitycenter.microsoft.com/api/indicators"
        body = {
            "indicatorValue": sha256, "indicatorType": "FileSha256",
            "action": "AlertAndBlock", "title": "BradlyAI Quarantine",
            "severity": "High",
            "description": reason or "Quarantined by BradlyAI",
            "application": "BradlyAI",
        }
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(), json=body)
            return {"status": r.status_code, "sha256": sha256, "response": r.text}
