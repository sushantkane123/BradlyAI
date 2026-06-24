"""AbuseIPDB API integration."""
import logging
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.threatintel import BaseThreatIntel

logger = logging.getLogger("bradlyai.threatintel.abuseipdb")


class AbuseIpDbClient(BaseThreatIntel):
    name = "abuseipdb"
    BASE = "https://api.abuseipdb.com/api/v2"

    def _headers(self) -> Dict[str, str]:
        return {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}

    def check(self, ip: str, max_age_days: int = 90) -> Dict[str, Any]:
        if self._guard() or not settings.ABUSEIPDB_API_KEY:
            return {"dry_run": True, "ip": ip, "abuse_score": 0,
                    "reason": "no API key or THREATINTEL_ENABLED=false"}
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{self.BASE}/check",
                      headers=self._headers(),
                      params={"ipAddress": ip, "maxAgeInDays": max_age_days})
            r.raise_for_status()
            data = r.json().get("data", {})
        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "verdict": "malicious" if data.get("abuseConfidenceScore", 0) >= 50 else "clean",
        }


def abuseipdb_check(ip: str) -> Dict[str, Any]:
    return AbuseIpDbClient().check(ip)
