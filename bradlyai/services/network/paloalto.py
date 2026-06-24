"""Palo Alto Networks Panorama / PAN-OS API integration.

Uses the XML API. Most production deployments should use Panorama as a
single point of integration for many firewalls.
"""
import logging
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET

import httpx

from bradlyai.config import settings
from bradlyai.services.network import BaseNetwork

logger = logging.getLogger("bradlyai.network.paloalto")


class PaloAltoNetwork(BaseNetwork):
    provider = "paloalto"

    def _cmd(self, xpath: str, element: str) -> ET.Element:
        url = f"{settings.PALOALTO_BASE_URL}/api/"
        params = {
            "type": "config", "action": "set",
            "key": settings.PALOALTO_API_KEY,
            "xpath": xpath, "element": element,
        }
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.get(url, params=params)
            r.raise_for_status()
            return ET.fromstring(r.text)

    def _block_ip(self, ip: str, duration_hours: Optional[int], reason: str) -> Dict[str, Any]:
        name = f"bradlyai_block_{ip.replace('.', '_')}"
        xpath = (f"/config/devices/entry/vsys/entry[@name='{settings.PALOALTO_VSYS}']/"
                 f"address/entry[@name='{name}']")
        element = f"<ip-netmask>{ip}/32</ip-netmask><description>{reason or 'BradlyAI block'}</description><tag><member>bradlyai</member></tag>"
        self._cmd(xpath, element)
        # Add to a denylist EDL or address-group
        group_xpath = (f"/config/devices/entry/vsys/entry[@name='{settings.PALOALTO_VSYS}']/"
                       f"address-group/entry[@name='bradlyai_denylist']")
        group_el = f"<static><member>{name}</member></static>"
        self._cmd(group_xpath, group_el)
        return {"status": "applied", "ip": ip, "address_object": name}

    def _unblock_ip(self, ip: str) -> Dict[str, Any]:
        name = f"bradlyai_block_{ip.replace('.', '_')}"
        xpath = (f"/config/devices/entry/vsys/entry[@name='{settings.PALOALTO_VSYS}']/"
                 f"address/entry[@name='{name}']")
        url = f"{settings.PALOALTO_BASE_URL}/api/"
        with httpx.Client(timeout=15, verify=False) as c:
            r = c.get(url, params={"type": "config", "action": "delete",
                                   "key": settings.PALOALTO_API_KEY, "xpath": xpath})
            return {"status": r.status_code, "ip": ip}

    def _quarantine_host(self, target: str) -> Dict[str, Any]:
        # In PA terms, "quarantine" = move to a quarantine VLAN / zone via DHCP option.
        # Most orgs handle this via a quarantine VLAN — return as informational stub.
        return {"status": "manual", "target": target,
                "note": "Move host to quarantine VLAN via DHCP/NAC"}
