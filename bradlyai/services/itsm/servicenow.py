"""ServiceNow Table API integration."""
import logging
import base64
from typing import Any, Dict, List, Optional

import httpx

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.itsm.servicenow")


class ServiceNowClient:
    def __init__(self):
        if not settings.ITSM_ENABLED:
            logger.info("ServiceNow called while ITSM_ENABLED=false — operations are dry-run")
        self.base = settings.SERVICENOW_INSTANCE_URL.rstrip("/")
        self.assignment_group = settings.SERVICENOW_DEFAULT_ASSIGNMENT_GROUP

    def _headers(self) -> Dict[str, str]:
        token = base64.b64encode(
            f"{settings.SERVICENOW_USERNAME}:{settings.SERVICENOW_PASSWORD}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}",
                "Accept": "application/json",
                "Content-Type": "application/json"}

    def _guard(self) -> bool:
        return not settings.ITSM_ENABLED or not self.base

    def create_incident(self, *, short_description: str, description: str = "",
                        urgency: Optional[str] = None, impact: Optional[str] = None,
                        assignment_group: Optional[str] = None,
                        additional_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "short_description": short_description,
                    "would_create_in": "incident"}
        body = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency or settings.SERVICENOW_URGENCY,
            "impact": impact or settings.SERVICENOW_IMPACT,
            "assignment_group": assignment_group or self.assignment_group,
        }
        if additional_fields:
            body.update(additional_fields)
        with httpx.Client(timeout=20, verify=False) as c:
            r = c.post(f"{self.base}/api/now/table/incident",
                       headers=self._headers(), json=body)
            r.raise_for_status()
            return r.json().get("result", {})

    def update_incident(self, sys_id: str, *, work_notes: Optional[str] = None,
                        state: Optional[str] = None,
                        additional_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "sys_id": sys_id, "would_update": True}
        body: Dict[str, Any] = {}
        if work_notes:
            body["work_notes"] = work_notes
        if state:
            body["state"] = state
        if additional_fields:
            body.update(additional_fields)
        with httpx.Client(timeout=20, verify=False) as c:
            r = c.patch(f"{self.base}/api/now/table/incident/{sys_id}",
                        headers=self._headers(), json=body)
            r.raise_for_status()
            return r.json().get("result", {})

    def get_incident(self, sys_id: str) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "sys_id": sys_id}
        with httpx.Client(timeout=20, verify=False) as c:
            r = c.get(f"{self.base}/api/now/table/incident/{sys_id}",
                      headers=self._headers())
            r.raise_for_status()
            return r.json().get("result", {})

    def list_incidents(self, query: str = "active=true", limit: int = 20) -> List[Dict[str, Any]]:
        if self._guard():
            return []
        with httpx.Client(timeout=20, verify=False) as c:
            r = c.get(f"{self.base}/api/now/table/incident",
                      headers=self._headers(),
                      params={"sysparm_query": query, "sysparm_limit": limit})
            r.raise_for_status()
            return r.json().get("result", [])


def servicenow_update_incident(sys_id: str, work_notes: str = "",
                               state: Optional[str] = None) -> Dict[str, Any]:
    return ServiceNowClient().update_incident(sys_id, work_notes=work_notes, state=state)
