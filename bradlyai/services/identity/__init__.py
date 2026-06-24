"""Identity/IAM dispatch — Azure AD (Entra ID), Okta."""
import logging
from typing import Any, Dict, Optional

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.identity")


class BaseIdentity:
    provider = "base"
    dry_run = True

    def __init__(self):
        self.dry_run = settings.IDENTITY_DRY_RUN

    def _guard(self) -> Optional[Dict[str, Any]]:
        if not settings.IDENTITY_ENABLED:
            return {"dry_run": True, "skipped": "IDENTITY_ENABLED=false",
                    "provider": self.provider}
        return None

    def disable_user(self, user_principal: str, reason: str = "") -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "user": user_principal, "action": "disable_user",
                    "would_execute": True}
        return self._disable_user(user_principal, reason)

    def enable_user(self, user_principal: str) -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "user": user_principal, "action": "enable_user",
                    "would_execute": True}
        return self._enable_user(user_principal)

    def revoke_sessions(self, user_principal: str) -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "user": user_principal, "action": "revoke_sessions",
                    "would_execute": True}
        return self._revoke_sessions(user_principal)

    def reset_password(self, user_principal: str) -> Dict[str, Any]:
        guard = self._guard()
        if guard is not None:
            return {**guard, "user": user_principal, "action": "reset_password",
                    "would_execute": True}
        return self._reset_password(user_principal)

    def _disable_user(self, u: str, r: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _enable_user(self, u: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _revoke_sessions(self, u: str) -> Dict[str, Any]:
        raise NotImplementedError
    def _reset_password(self, u: str) -> Dict[str, Any]:
        raise NotImplementedError


def get_identity_client() -> BaseIdentity:
    provider = (settings.IDENTITY_PROVIDER or "none").lower()
    if provider == "azure_ad":
        from bradlyai.services.identity.azure_ad import AzureAdIdentity
        return AzureAdIdentity()
    if provider == "okta":
        from bradlyai.services.identity.okta import OktaIdentity
        return OktaIdentity()
    return BaseIdentity()
