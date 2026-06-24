"""Okta identity actions."""
import logging
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.identity import BaseIdentity

logger = logging.getLogger("bradlyai.identity.okta")


class OktaIdentity(BaseIdentity):
    provider = "okta"

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"SSWS {settings.OKTA_API_TOKEN}",
                "Accept": "application/json",
                "Content-Type": "application/json"}

    def _user_id(self, login: str) -> str:
        url = f"https://{settings.OKTA_DOMAIN}/api/v1/users/{login}"
        with httpx.Client(timeout=15) as c:
            r = c.get(url, headers=self._headers())
            r.raise_for_status()
            return r.json()["id"]

    def _disable_user(self, login: str, reason: str) -> Dict[str, Any]:
        uid = self._user_id(login)
        url = f"https://{settings.OKTA_DOMAIN}/api/v1/users/{uid}/lifecycle/suspend"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers())
            return {"status": r.status_code, "user": login, "uid": uid}

    def _enable_user(self, login: str) -> Dict[str, Any]:
        uid = self._user_id(login)
        url = f"https://{settings.OKTA_DOMAIN}/api/v1/users/{uid}/lifecycle/reactivate"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers())
            return {"status": r.status_code, "user": login, "uid": uid}

    def _revoke_sessions(self, login: str) -> Dict[str, Any]:
        uid = self._user_id(login)
        url = f"https://{settings.OKTA_DOMAIN}/api/v1/users/{uid}/sessions"
        with httpx.Client(timeout=15) as c:
            r = c.delete(url, headers=self._headers())
            return {"status": r.status_code, "user": login, "uid": uid}

    def _reset_password(self, login: str) -> Dict[str, Any]:
        uid = self._user_id(login)
        url = f"https://{settings.OKTA_DOMAIN}/api/v1/users/{uid}/lifecycle/reset_password"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers(), json={"sendEmail": False})
            return {"status": r.status_code, "user": login, "uid": uid}
