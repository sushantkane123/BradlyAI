"""Azure AD (Entra ID) identity actions."""
import logging
import time
from typing import Any, Dict

import httpx

from bradlyai.config import settings
from bradlyai.services.identity import BaseIdentity

logger = logging.getLogger("bradlyai.identity.azure_ad")


class AzureAdIdentity(BaseIdentity):
    provider = "azure_ad"
    _TOKEN: Dict[str, Any] = {"value": None, "expires_at": 0}

    def _get_token(self) -> str:
        now = time.time()
        if self._TOKEN["value"] and self._TOKEN["expires_at"] > now + 60:
            return self._TOKEN["value"]
        url = f"https://login.microsoftonline.com/{settings.AZURE_AD_TENANT_ID}/oauth2/v2.0/token"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, data={
                "client_id": settings.AZURE_AD_CLIENT_ID,
                "client_secret": settings.AZURE_AD_CLIENT_SECRET,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            })
            r.raise_for_status()
            data = r.json()
        self._TOKEN = {"value": data["access_token"], "expires_at": now + data.get("expires_in", 3600)}
        return self._TOKEN["value"]

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json"}

    def _user_id(self, upn: str) -> str:
        url = f"https://graph.microsoft.com/v1.0/users/{upn}"
        with httpx.Client(timeout=15) as c:
            r = c.get(url, headers=self._headers())
            r.raise_for_status()
            return r.json()["id"]

    def _disable_user(self, upn: str, reason: str) -> Dict[str, Any]:
        uid = self._user_id(upn)
        url = f"https://graph.microsoft.com/v1.0/users/{uid}"
        with httpx.Client(timeout=15) as c:
            r = c.patch(url, headers=self._headers(), json={"accountEnabled": False})
            return {"status": r.status_code, "user": upn, "uid": uid}

    def _enable_user(self, upn: str) -> Dict[str, Any]:
        uid = self._user_id(upn)
        url = f"https://graph.microsoft.com/v1.0/users/{uid}"
        with httpx.Client(timeout=15) as c:
            r = c.patch(url, headers=self._headers(), json={"accountEnabled": True})
            return {"status": r.status_code, "user": upn, "uid": uid}

    def _revoke_sessions(self, upn: str) -> Dict[str, Any]:
        uid = self._user_id(upn)
        url = f"https://graph.microsoft.com/v1.0/users/{uid}/revokeSignInSessions"
        with httpx.Client(timeout=15) as c:
            r = c.post(url, headers=self._headers())
            return {"status": r.status_code, "user": upn, "uid": uid}

    def _reset_password(self, upn: str) -> Dict[str, Any]:
        # Returns a temporary password (caller must communicate to user).
        import secrets
        uid = self._user_id(upn)
        temp_pwd = secrets.token_urlsafe(16) + "A1!"
        url = f"https://graph.microsoft.com/v1.0/users/{uid}"
        body = {"passwordProfile": {"forceChangePasswordNextSignIn": True,
                                     "password": temp_pwd}}
        with httpx.Client(timeout=15) as c:
            r = c.patch(url, headers=self._headers(), json=body)
            return {"status": r.status_code, "user": upn, "temp_password": temp_pwd}
