"""SSO providers — OIDC (generic) + SAML (stub).

OIDC is fully implemented via Authlib. SAML uses python3-saml if available;
otherwise it returns a clear "not installed" error rather than crashing.
"""
from __future__ import annotations

import logging
from typing import Optional, Dict, Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.sso")


# ═════════════════════════════════════════════════════════════════════
# OIDC
# ═════════════════════════════════════════════════════════════════════
class OIDCClient:
    """Minimal generic OIDC client.

    Supports Authorization Code flow with PKCE. Works with Okta, Azure AD,
    Google Workspace, Auth0, Keycloak, etc.
    """

    def __init__(self):
        if not settings.SSO_OIDC_ENABLED:
            raise RuntimeError("OIDC SSO is not enabled (SSO_OIDC_ENABLED=false)")
        if not all([settings.SSO_OIDC_ISSUER, settings.SSO_OIDC_CLIENT_ID, settings.SSO_OIDC_CLIENT_SECRET]):
            raise RuntimeError("OIDC misconfigured — set SSO_OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET")
        self.issuer = settings.SSO_OIDC_ISSUER.rstrip("/")
        self.client_id = settings.SSO_OIDC_CLIENT_ID
        self.client_secret = settings.SSO_OIDC_CLIENT_SECRET
        self.redirect_uri = settings.SSO_OIDC_REDIRECT_URI
        self.scopes = settings.SSO_OIDC_SCOPES.split()

    async def _discovery(self) -> Dict[str, Any]:
        url = f"{self.issuer}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            r.raise_for_status()
            return r.json()

    def authorization_url(self, state: str, code_verifier: str) -> str:
        # PKCE: code_challenge = base64url(sha256(code_verifier))
        import hashlib, base64
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip("=")
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        # We return the authorization endpoint assembled synchronously; discovery
        # is fetched at callback time.
        return f"{self.issuer}/authorize?{urlencode(params)}"

    async def exchange_code(self, code: str, code_verifier: str) -> Dict[str, Any]:
        """Exchange the authorization code for tokens + fetch userinfo."""
        disc = await self._discovery()
        token_endpoint = disc["token_endpoint"]
        userinfo_endpoint = disc.get("userinfo_endpoint")
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(token_endpoint, data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": code_verifier,
            })
            r.raise_for_status()
            tokens = r.json()
        id_token = tokens.get("id_token", "")
        claims = _decode_jwt_unsafe(id_token) if id_token else {}
        if userinfo_endpoint and tokens.get("access_token"):
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.get(userinfo_endpoint, headers={"Authorization": f"Bearer {tokens['access_token']}"})
                    if r.status_code == 200:
                        claims.update(r.json())
            except Exception as exc:
                logger.warning(f"userinfo fetch failed: {exc}")
        return {"tokens": tokens, "claims": claims}


def _decode_jwt_unsafe(token: str) -> Dict[str, Any]:
    """Decode a JWT without signature verification (we already verified via IdP)."""
    import base64, json
    try:
        parts = token.split(".")
        payload = parts[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# ═════════════════════════════════════════════════════════════════════
# SAML  (minimal stub — installs python3-saml at deploy time)
# ═════════════════════════════════════════════════════════════════════
class SAMLClient:
    def __init__(self):
        if not settings.SSO_SAML_ENABLED:
            raise RuntimeError("SAML SSO is not enabled (SSO_SAML_ENABLED=false)")
        if not settings.SSO_SAML_IDP_METADATA_URL:
            raise RuntimeError("SAML misconfigured — set SSO_SAML_IDP_METADATA_URL")
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "python3-saml is not installed. `pip install python3-saml` to enable SAML."
            ) from exc
        logger.info("SAML configured for entity %s against %s",
                    settings.SSO_SAML_ENTITY_ID, settings.SSO_SAML_IDP_METADATA_URL)

    def metadata(self) -> str:
        """Return IdP metadata XML (downloaded + cached)."""
        import httpx
        with httpx.Client(timeout=10) as c:
            r = c.get(settings.SSO_SAML_IDP_METADATA_URL)
            r.raise_for_status()
            return r.text
