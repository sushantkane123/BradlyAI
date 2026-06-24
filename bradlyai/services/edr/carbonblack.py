"""VMware Carbon Black Cloud integration."""
import logging
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.edr import BaseEDR

logger = logging.getLogger("bradlyai.edr.carbonblack")


class CarbonBlackEDR(BaseEDR):
    provider = "carbonblack"
    ORG_KEY = "test"          # override per-deployment

    def _headers(self) -> Dict[str, str]:
        import secrets, hashlib, hmac, time
        secret = settings.CARBONBLACK_API_SECRET
        auth = f"{settings.CARBONBLACK_API_ID}/{secrets.token_hex(8)}"
        ts = str(int(time.time()))
        sig = hmac.new(secret.encode(), auth.encode() + ts.encode(), hashlib.sha256).hexdigest()
        return {"X-Auth-Token": f"{auth}/{ts}/{sig}",
                "Content-Type": "application/json"}

    def _device_id_for_host(self, hostname: str) -> str:
        url = f"{settings.CARBONBLACK_BASE_URL}/api/investigate/v1/orgs/{self.ORG_KEY}/devices/_search"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(),
                       json={"query": f"hostname:{hostname}", "rows": 1})
            r.raise_for_status()
            devs = r.json().get("results", [])
        return devs[0]["id"] if devs else hostname

    def _isolate_host(self, host_id: str, reason: str) -> Dict[str, Any]:
        device_id = self._device_id_for_host(host_id)
        url = f"{settings.CARBONBLACK_BASE_URL}/api/livequery/v1/orgs/{self.ORG_KEY}/device_actions"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(), json={
                "action_type": "QUARANTINE", "device_id": [device_id],
                "note": reason or "BradlyAI containment",
            })
            return {"status": r.status_code, "device_id": device_id, "response": r.json()}

    def _release_host(self, host_id: str) -> Dict[str, Any]:
        device_id = self._device_id_for_host(host_id)
        url = f"{settings.CARBONBLACK_BASE_URL}/api/livequery/v1/orgs/{self.ORG_KEY}/device_actions"
        with httpx.Client(timeout=30) as c:
            r = c.post(url, headers=self._headers(), json={
                "action_type": "UNQUARANTINE", "device_id": [device_id],
                "note": "BradlyAI release",
            })
            return {"status": r.status_code, "device_id": device_id, "response": r.json()}

    def _quarantine_file(self, sha256: str, reason: str) -> Dict[str, Any]:
        url = f"{settings.CARBONBLACK_BASE_URL}/api/policy/v1/orgs/{self.ORG_KEY}/reputation"
        body = {"sha256_hash": [sha256], "reputation_override": "KNOWN_MALWARE",
                "description": reason or "BradlyAI quarantine"}
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(), json=body)
            return {"status": r.status_code, "sha256": sha256, "response": r.json()}
