"""Jira Cloud REST API integration (two-way)."""
import logging
import base64
from typing import Any, Dict, List, Optional

import httpx

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.itsm.jira")


class JiraClient:
    def __init__(self):
        self.base = settings.JIRA_URL.rstrip("/")
        self.project = settings.JIRA_DEFAULT_PROJECT_KEY

    def _headers(self) -> Dict[str, str]:
        token = base64.b64encode(
            f"{settings.JIRA_USERNAME}:{settings.JIRA_API_TOKEN}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}",
                "Accept": "application/json",
                "Content-Type": "application/json"}

    def _guard(self) -> bool:
        return not settings.ITSM_ENABLED or not self.base

    def create_issue(self, *, summary: str, description: str = "",
                     issue_type: str = "Task",
                     project: Optional[str] = None,
                     additional_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "summary": summary, "would_create_in": project or self.project}
        body = {
            "fields": {
                "project": {"key": project or self.project},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
            }
        }
        if additional_fields:
            body["fields"].update(additional_fields)
        with httpx.Client(timeout=20) as c:
            r = c.post(f"{self.base}/rest/api/3/issue", headers=self._headers(), json=body)
            r.raise_for_status()
            return r.json()

    def update_issue(self, key: str, *, fields: Dict[str, Any]) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "key": key, "fields": fields}
        with httpx.Client(timeout=20) as c:
            r = c.put(f"{self.base}/rest/api/3/issue/{key}",
                      headers=self._headers(), json={"fields": fields})
            r.raise_for_status()
            return {"status": r.status_code, "key": key}

    def add_comment(self, key: str, comment: str) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "key": key, "comment": comment}
        body = {"body": {"type": "doc", "version": 1,
                         "content": [{"type": "paragraph",
                                      "content": [{"type": "text", "text": comment}]}]}}
        with httpx.Client(timeout=20) as c:
            r = c.post(f"{self.base}/rest/api/3/issue/{key}/comment",
                       headers=self._headers(), json=body)
            r.raise_for_status()
            return r.json()

    def transition(self, key: str, transition_id: str) -> Dict[str, Any]:
        if self._guard():
            return {"dry_run": True, "key": key, "transition": transition_id}
        with httpx.Client(timeout=20) as c:
            r = c.post(f"{self.base}/rest/api/3/issue/{key}/transitions",
                       headers=self._headers(), json={"transition": {"id": transition_id}})
            r.raise_for_status()
            return {"status": r.status_code, "key": key}


def jira_create_issue(project: str, summary: str, description: str = "",
                      issue_type: str = "Task") -> Dict[str, Any]:
    return JiraClient().create_issue(summary=summary, description=description,
                                     issue_type=issue_type, project=project)
