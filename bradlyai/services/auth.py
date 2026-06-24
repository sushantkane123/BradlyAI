"""Auth core — JWT issuance, validation, MFA, lockout, API-key verification.

This module is the single source of truth for *who is the caller* on every
request. Routers depend on `get_current_user` / `require_permission`.
"""
from __future__ import annotations

import datetime
import logging
from typing import Optional, List

import jwt
import pyotp
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.database import get_db
from bradlyai.models.user import UserModel
from bradlyai.models.api_key import ApiKeyModel
from bradlyai.models.role import UserRoleModel, RoleModel, PermissionModel
from bradlyai.services.password import verify_password

logger = logging.getLogger("bradlyai.auth")

# ── FastAPI security primitives ─────────────────────────────────────
# tokenUrl points at the local-password login endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ═════════════════════════════════════════════════════════════════════
# JWT
# ═════════════════════════════════════════════════════════════════════
def create_access_token(user: UserModel, extra_claims: Optional[dict] = None) -> str:
    """Create a short-lived access JWT."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": user.id,
        "username": user.username,
        "is_admin": user.is_admin,
        "tenant_id": user.tenant_id or settings.DEFAULT_TENANT_ID,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=settings.AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.AUTH_JWT_SECRET, algorithm=settings.AUTH_JWT_ALGORITHM)


def create_refresh_token(user: UserModel) -> str:
    """Create a long-lived refresh JWT."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": user.id,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(days=settings.AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS)).timestamp()),
    }
    return jwt.encode(payload, settings.AUTH_JWT_SECRET, algorithm=settings.AUTH_JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode + validate a JWT. Raises HTTPException on failure."""
    try:
        return jwt.decode(token, settings.AUTH_JWT_SECRET, algorithms=[settings.AUTH_JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


# ═════════════════════════════════════════════════════════════════════
# Login / Lockout / MFA
# ═════════════════════════════════════════════════════════════════════
def authenticate_user(db: Session, username: str, password: str, mfa_code: Optional[str] = None) -> UserModel:
    """Validate username/password (+ optional MFA). Applies lockout policy.

    Returns the UserModel on success; raises HTTPException on failure.
    """
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        # Don't leak which half was wrong — generic message
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")

    # ── Lockout check ──
    now = datetime.datetime.now(datetime.timezone.utc)
    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked until {user.locked_until.isoformat()}",
        )

    # ── Password (NULL for SSO-only accounts) ──
    if not user.password_hash or not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= settings.AUTH_MAX_FAILED_LOGINS:
            user.locked_until = now + datetime.timedelta(minutes=settings.AUTH_LOCKOUT_MINUTES)
            user.failed_login_count = 0
            logger.warning(f"User {username} locked until {user.locked_until}")
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # ── MFA ──
    if user.mfa_enabled:
        if not mfa_code:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="MFA required", headers={"X-MFA-Required": "true"})
        if not user.mfa_secret or not pyotp.TOTP(user.mfa_secret).verify(mfa_code, valid_window=1):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    # Success — reset counters
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()
    return user


# ═════════════════════════════════════════════════════════════════════
# Current-user dependency (Bearer JWT *or* X-API-Key)
# ═════════════════════════════════════════════════════════════════════
def _resolve_api_key(db: Session, raw_key: str) -> Optional[UserModel]:
    key_hash = ApiKeyModel.hash_secret(raw_key)
    row = db.query(ApiKeyModel).filter(ApiKeyModel.key_hash == key_hash, ApiKeyModel.is_active == True).first()
    if row is None:
        return None
    if row.expires_at and row.expires_at < datetime.datetime.now(datetime.timezone.utc):
        return None
    row.last_used_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    if row.owner_user_id:
        return db.query(UserModel).filter(UserModel.id == row.owner_user_id).first()
    # Service-only key — synthesize a virtual admin-ish user via is_admin flag from scopes
    pseudo = UserModel(id=f"apikey:{row.id}", username=f"svc:{row.name}", email="", is_active=True,
                       is_admin="admin" in (row.scopes or ""), tenant_id=row.tenant_id)
    return pseudo


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    bearer: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header),
) -> UserModel:
    """Resolve the current caller from Bearer JWT or X-API-Key.

    If AUTH_ENABLED=false (single-tenant dev mode), returns a synthetic admin.
    """
    if not settings.AUTH_ENABLED:
        return UserModel(id="anonymous", username="anonymous", email="dev@local",
                         is_active=True, is_admin=True, tenant_id=settings.DEFAULT_TENANT_ID)

    if api_key:
        user = _resolve_api_key(db, api_key)
        if user:
            return user

    if not bearer:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})

    payload = decode_token(bearer)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")

    user = db.query(UserModel).filter(UserModel.id == payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found / disabled")
    return user


def get_current_tenant_id(user: UserModel = Depends(get_current_user)) -> str:
    """Return the active tenant id for this request (used as DB filter)."""
    return user.tenant_id or settings.DEFAULT_TENANT_ID


# ═════════════════════════════════════════════════════════════════════
# RBAC
# ═════════════════════════════════════════════════════════════════════
def user_permissions(db: Session, user: UserModel) -> set[tuple[str, str]]:
    """Return set of (resource, action) pairs the user is granted."""
    if user.is_admin:
        return {("*", "*")}      # admin has all
    perms: set[tuple[str, str]] = set()
    links = db.query(UserRoleModel).filter(UserRoleModel.user_id == user.id).all()
    for link in links:
        role = db.query(RoleModel).filter(RoleModel.id == link.role_id).first()
        if role is None:
            continue
        for p in role.permissions:
            perms.add((p.resource, p.action))
    return perms


def require_permission(resource: str, action: str):
    """FastAPI dependency factory enforcing (resource, action) RBAC."""
    def _checker(user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
        perms = user_permissions(db, user)
        if ("*", "*") in perms or (resource, action) in perms or (resource, "*") in perms:
            return user
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Missing permission: {resource}:{action}")
    return _checker


def seed_default_roles(db: Session) -> None:
    """Create the built-in roles + permissions on first boot."""
    builtins = {
        "admin": {"description": "Full access", "permissions": [("*", "*")]},
        "analyst_l1": {
            "description": "L1 triage analyst — auto-closable alerts, create cases",
            "permissions": [
                ("alerts", "read"), ("alerts", "write"),
                ("cases", "read"), ("cases", "write"),
                ("playbooks", "read"), ("playbooks", "run"),
                ("audit", "read"),
            ],
        },
        "analyst_l2": {
            "description": "L2 investigator — full case management + response actions",
            "permissions": [
                ("alerts", "read"), ("alerts", "write"),
                ("cases", "read"), ("cases", "write"), ("cases", "approve"),
                ("playbooks", "read"), ("playbooks", "run"), ("playbooks", "approve"),
                ("response", "read"), ("response", "execute"),
                ("audit", "read"),
            ],
        },
        "responder": {
            "description": "External responder — read-only with case updates",
            "permissions": [("cases", "read"), ("cases", "comment"), ("alerts", "read")],
        },
        "auditor": {
            "description": "Compliance auditor — read-only across the board",
            "permissions": [
                ("alerts", "read"), ("cases", "read"), ("audit", "read"),
                ("playbooks", "read"), ("response", "read"), ("reports", "read"),
            ],
        },
    }
    for name, spec in builtins.items():
        existing = db.query(RoleModel).filter(RoleModel.name == name).first()
        if existing:
            continue
        role = RoleModel(name=name, description=spec["description"], is_builtin=True,
                         tenant_id=settings.DEFAULT_TENANT_ID)
        for resource, action in spec["permissions"]:
            role.permissions.append(PermissionModel(resource=resource, action=action))
        db.add(role)
    db.commit()
