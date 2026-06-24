"""AlienVault OTX (Open Threat Exchange) integration."""
import logging
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.threatintel import BaseThreatIntel

logger = logging.getLogger("bradlyai.threatintel.otx")


class OTXClient(BaseThreatIntel):
    name = "otx"
    BASE = "https://otx.alienvault.com/api/v1"

    def _headers(self) -> Dict[str, str]:
        return {"X-OTX-API-KEY": settings.OTX_API_KEY}

    def ip_general(self, ip: str) -> Dict[str, Any]:
        if self._guard() or not settings.OTX_API_KEY:
            return {"dry_run": True, "ip": ip, "pulses": 0,
                    "reason": "no API key or THREATINTEL_ENABLED=false"}
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{self.BASE}/indicators/IPv4/{ip}/general",
                      headers=self._headers())
            r.raise_for_status()
            data = r.json()
        return {
            "ip": ip,
            "pulses": data.get("pulse_info", {}).get("count", 0),
            "verdict": "malicious" if data.get("pulse_info", {}).get("count", 0) > 0 else "clean",
            "reputation": data.get("reputation"),
            "country": data.get("country_name"),
            "asn": data.get("asn"),
        }


def otx_lookup_ip(ip: str) -> Dict[str, Any]:
    return OTXClient().ip_general(ip)
