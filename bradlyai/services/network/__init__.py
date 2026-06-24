"""Network containment dispatch — Palo Alto, Fortinet, Cisco ASA, Check Point."""
import logging
from typing import Any, Dict, Optional

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.network")


class BaseNetwork:
    provider = "base"
    dry_run = True

    def __init__(self):
        self.dry_run = settings.NETWORK_DRY_RUN

    def _guard(self) -> Optional[Dict[str, Any]]:
        if not settings.NETWORK_ENABLED:
            return {"dry_run": True, "skipped": "NETWORK_ENABLED=false",
                    "provider": self.provider}
        return None

    def block_ip(self, ip: str, duration_hours: Optional[int] = None,
                 reason: str = "") -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "ip": ip, "action": "block_ip",
                    "duration_hours": duration_hours, "would_execute": True}
        return self._block_ip(ip, duration_hours, reason)

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "ip": ip, "action": "unblock_ip", "would_execute": True}
        return self._unblock_ip(ip)

    def quarantine_host(self, ip_or_host: str) -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "target": ip_or_host, "action": "quarantine_host", "would_execute": True}
        return self._quarantine_host(ip_or_host)

    def _block_ip(self, ip: str, duration_hours: Optional[int], reason: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _unblock_ip(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _quarantine_host(self, target: str) -> Dict[str, Any]:
        raise NotImplementedError


def get_network_client() -> BaseNetwork:
    provider = (settings.NETWORK_PROVIDER or "none").lower()
    if provider == "paloalto":
        from bradlyai.services.network.paloalto import PaloAltoNetwork
        return PaloAltoNetwork()
    if provider == "fortinet":
        from bradlyai.services.network.fortinet import FortinetNetwork
        return FortinetNetwork()
    if provider == "cisco_asa":
        from bradlyai.services.network.cisco import CiscoAsaNetwork
        return CiscoAsaNetwork()
    if provider == "checkpoint":
        from bradlyai.services.network.checkpoint import CheckPointNetwork
        return CheckPointNetwork()
    return BaseNetwork()
