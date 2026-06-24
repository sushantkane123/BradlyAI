"""Zendesk Support API integration."""
import logging
import base64
from typing import Any, Dict, Optional

import httpx

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.itsm.zendesk")


class ZendeskClient:
    def __init__(self):
        self.base = f"https://{settings.ZENDESK_SUBDOMAIN}.zendesk.com/api/v2"

    def _headers(self) -> Dict[str, str]:
        token = base64.b64encode(
            f"{settings.ZENDESK_EMAIL}/token:{settings.ZENDESK_API_TOKEN}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}",
                "Content-Type": "application/json"}

    def _guard(self) -> bool:
        return not settings.ITSM_ENABLED or not settings.ZENDESK_SUBDOMAIN

    def create_ticket(self, *, subject: str, comment: str, priority: str = "normal",
                      requester_email: Optional[str] = None,
                      additional_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "subject": subject}
        body: Dict[str, Any] = {
            "ticket": {
                "subject": subject,
                "comment": {"body": comment},
                "priority": priority,
            }
        }
        if requester_email:
            body["ticket"]["requester"] = {"email": requester_email}
        if additional_fields:
            body["ticket"].update(additional_fields)
        with httpx.Client(timeout=20) as c:
            r = c.post(f"{self.base}/tickets.json", headers=self._headers(), json=body)
            r.raise_for_status()
            return r.json().get("ticket", {})

    def update_ticket(self, ticket_id: str, *, comment: Optional[str] = None,
                      status: Optional[str] = None,
                      additional_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "ticket_id": ticket_id}
        body: Dict[str, Any] = {}
        if comment:
            body["comment"] = {"body": comment}
        if status:
            body["status"] = status
        if additional_fields:
            body.update(additional_fields)
        with httpx.Client(timeout=20) as c:
            r = c.put(f"{self.base}/tickets/{ticket_id}.json",
                      headers=self._headers(), json={"ticket": body})
            r.raise_for_status()
            return r.json().get("ticket", {})
