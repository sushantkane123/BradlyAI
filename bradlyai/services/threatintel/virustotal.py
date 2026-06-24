"""VirusTotal API v3 — IP / domain / file hash lookup."""
import logging
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.threatintel import BaseThreatIntel

logger = logging.getLogger("bradlyai.threatintel.virustotal")


class VirusTotalClient(BaseThreatIntel):
    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": settings.VIRUSTOTAL_API_KEY, "Accept": "application/json"}

    def ip_address(self, ip: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{self.BASE}/ip_addresses/{ip}", headers=self._headers())
            r.raise_for_status()
            return r.json()

    def domain(self, domain: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{self.BASE}/domains/{domain}", headers=self._headers())
            r.raise_for_status()
            return r.json()

    def file(self, sha256: str) -> Dict[str, Any]:
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{self.BASE}/files/{sha256}", headers=self._headers())
            r.raise_for_status()
            return r.json()

    def summary(self, ip: str) -> Dict[str, Any]:
        if self._guard() or not settings.VIRUSTOTAL_API_KEY:
            return {"dry_run": True, "ip": ip, "verdict": "unknown",
                    "reason": "no API key or THREATINTEL_ENABLED=false"}
        try:
            data = self.ip_address(ip)
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "ip": ip, "verdict": "malicious" if stats.get("malicious", 0) > 0 else "clean",
                "stats": stats,
                "country": data.get("data", {}).get("attributes", {}).get("country"),
                "as_owner": data.get("data", {}).get("attributes", {}).get("as_owner"),
            }
        except Exception as exc:
            return {"ip": ip, "verdict": "error", "error": str(exc)}


def vt_lookup_ip(ip: str) -> Dict[str, Any]:
    return VirusTotalClient().summary(ip)
