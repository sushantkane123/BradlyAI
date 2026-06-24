"""Fortinet FortiGate REST API integration."""
import logging
from typing import Any, Dict, Optional

import httpx

from bradlyai.config import settings
from bradlyai.services.network import BaseNetwork

logger = logging.getLogger("bradlyai.network.fortinet")


class FortinetNetwork(BaseNetwork):
    provider = "fortinet"

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {settings.FORTINET_API_TOKEN}",
                "Content-Type": "application/json"}

    def _block_ip(self, ip: str, duration_hours: Optional[int], reason: str) -> Dict[str, Any]:
        name = f"bradlyai_block_{ip.replace('.', '_')}"
        url = f"{settings.FORTINET_BASE_URL}/api/v2/cmdb/firewall/address"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(url, headers=self._headers(), json={
                "name": name, "type": "iprange", "start-ip": ip, "end-ip": ip,
                "comment": reason or "BradlyAI block",
            })
            r.raise_for_status()
            addr_resp = r.json()
        # Add to a denylist group
        grp_url = f"{settings.FORTINET_BASE_URL}/api/v2/cmdb/firewall/addrgrp"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.post(grp_url, headers=self._headers(), json={
                "name": "bradlyai_denylist", "member": [{"name": name}],
            })
            grp_resp = r.json()
        return {"status": "applied", "ip": ip, "address": addr_resp, "group": grp_resp}

    def _unblock_ip(self, ip: str) -> Dict[str, Any]:
        name = f"bradlyai_block_{ip.replace('.', '_')}"
        url = f"{settings.FORTINET_BASE_URL}/api/v2/cmdb/firewall/address/{name}"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.delete(url, headers=self._headers())
            return {"status": r.status_code, "ip": ip}

    def _quarantine_host(self, target: str) -> Dict[str, Any]:
        return {"status": "manual", "target": target,
                "note": "Assign host to quarantine VLAN via FortiSwitch VLAN policy"}
