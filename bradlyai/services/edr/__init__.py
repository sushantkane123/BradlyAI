"""EDR integration dispatch — CrowdStrike, Defender, SentinelOne, Carbon Black."""
import logging
from typing import Any, Dict, Optional

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.edr")


class BaseEDR:
    provider = "base"
    dry_run = True

    def __init__(self):
        self.dry_run = settings.EDR_DRY_RUN

    def _guard(self) -> Optional[Dict[str, Any]]:
        """If disabled or dry-run, return a safe stub response."""
        if not settings.EDR_ENABLED:
            return {"dry_run": True, "skipped": "EDR_ENABLED=false",
                    "provider": self.provider}
        return None

    def isolate_host(self, host_id: str, reason: str = "") -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "host_id": host_id, "action": "isolate_host", "would_execute": True}
        return self._isolate_host(host_id, reason)

    def release_host(self, host_id: str) -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "host_id": host_id, "action": "release_host", "would_execute": True}
        return self._release_host(host_id)

    def quarantine_file(self, sha256: str, reason: str = "") -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "sha256": sha256, "action": "quarantine_file", "would_execute": True}
        return self._quarantine_file(sha256, reason)

    def get_processes(self, host_id: str, since: Optional[str] = None) -> Dict[str, Any]:
        return {"dry_run": True, "provider": self.provider, "host_id": host_id, "processes": []}

    def _isolate_host(self, host_id: str, reason: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _release_host(self, host_id: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _quarantine_file(self, sha256: str, reason: str) -> Dict[str, Any]:
        raise NotImplementedError


def get_edr_client() -> BaseEDR:
    """Return the configured EDR client based on settings.EDR_PROVIDER."""
    provider = (settings.EDR_PROVIDER or "none").lower()
    if provider == "crowdstrike":
        from bradlyai.services.edr.crowdstrike import CrowdStrikeEDR
        return CrowdStrikeEDR()
    if provider == "defender":
        from bradlyai.services.edr.defender import DefenderEDR
        return DefenderEDR()
    if provider == "sentinelone":
        from bradlyai.services.edr.sentinelone import SentinelOneEDR
        return SentinelOneEDR()
    if provider == "carbonblack":
        from bradlyai.services.edr.carbonblack import CarbonBlackEDR
        return CarbonBlackEDR()
    # "none" or unknown — return base stub (all calls return dry-run stub)
    return BaseEDR()
