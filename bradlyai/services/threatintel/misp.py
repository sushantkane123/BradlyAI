"""MISP (Malware Information Sharing Platform) integration."""
import logging
from typing import Any, Dict, List

import httpx

from bradlyai.config import settings
from bradlyai.services.threatintel import BaseThreatIntel

logger = logging.getLogger("bradlyai.threatintel.misp")


class MISPClient(BaseThreatIntel):
    name = "misp"
    _HEADERS_CACHE: Dict[str, str] = {}

    def _headers(self) -> Dict[str, str]:
        if self._HEADERS_CACHE:
            return self._HEADERS_CACHE
        # MISP uses the API key in Authorization OR a custom header
        # We'll use Authorization with the key as user (some MISP versions).
        # Safer: use the X-API-Key header (preferred in modern MISP).
        return {"X-API-Key": settings.MISP_API_KEY,
                "Accept": "application/json",
                "Content-Type": "application/json"}

    def search_ip(self, ip: str) -> List[Dict[str, Any]]:
        if self._guard() or not settings.MISP_API_KEY or not settings.MISP_URL:
            return []
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(f"{settings.MISP_URL.rstrip('/')}/attributes/restSearch",
                       headers=self._headers(),
                       json={"value": ip, "type": "ip-dst"})
            r.raise_for_status()
            attrs = r.json().get("response", {}).get("Attribute", [])
        return [{
            "value": a.get("value"), "category": a.get("category"),
            "type": a.get("type"), "comment": a.get("comment"),
            "tag": a.get("Tag", [{}])[0].get("name") if a.get("Tag") else None,
        } for a in attrs]


def misp_search_ip(ip: str) -> List[Dict[str, Any]]:
    return MISPClient().search_ip(ip)
