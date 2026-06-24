"""Threat intel base + unified dispatcher."""
from typing import Any, Dict, Optional


class BaseThreatIntel:
    name = "base"

    def _enabled(self) -> bool:
        from bradlyai.config import settings
        return settings.THREATINTEL_ENABLED

    def _guard(self) -> bool:
        return not self._enabled()


def lookup_ip(ip: str, sources: Optional[list] = None) -> Dict[str, Any]:
    """Query all enabled threat-intel sources for an IP."""
    if sources is None:
        sources = ["virustotal", "abuseipdb", "otx", "greynoise"]
    results: Dict[str, Any] = {}
    if "virustotal" in sources:
        try:
            from bradlyai.services.threatintel.virustotal import vt_lookup_ip
            results["virustotal"] = vt_lookup_ip(ip)
        except Exception as exc:
            results["virustotal"] = {"error": str(exc)}
    if "abuseipdb" in sources:
        try:
            from bradlyai.services.threatintel.abuseipdb import abuseipdb_check
            results["abuseipdb"] = abuseipdb_check(ip)
        except Exception as exc:
            results["abuseipdb"] = {"error": str(exc)}
    if "otx" in sources:
        try:
            from bradlyai.services.threatintel.otx import otx_lookup_ip
            results["otx"] = otx_lookup_ip(ip)
        except Exception as exc:
            results["otx"] = {"error": str(exc)}
    if "greynoise" in sources:
        try:
            from bradlyai.services.greynoise_client import greynoise_client
            results["greynoise"] = greynoise_client.classify(ip)
        except Exception as exc:
            results["greynoise"] = {"error": str(exc)}
    if "misp" in sources:
        try:
            from bradlyai.services.threatintel.misp import misp_search_ip
            results["misp"] = misp_search_ip(ip)
        except Exception as exc:
            results["misp"] = {"error": str(exc)}
    return results
