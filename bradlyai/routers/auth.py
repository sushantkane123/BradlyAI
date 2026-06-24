"""Auth router — local login + MFA + SSO (OIDC/SAML) + API-key management."""
import datetime
import logging
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.database import get_db
from bradlyai.models.user import UserModel
from bradlyai.models.api_key import ApiKeyModel
from bradlyai.models.role import RoleModel, UserRoleModel
from bradlyai.services.auth import (
    authenticate_user, create_access_token, create_refresh_token,
    decode_token, get_current_user, require_permission,
    seed_default_roles,
)
from bradlyai.services.password import hash_password, verify_password
from bradlyai.services.tenant import seed_default_tenant
from bradlyai.services.sso import OIDCClient

logger = logging.getLogger("bradlyai.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Schemas ────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = settings.AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str
    password: str = Field(min_length=settings.AUTH_PASSWORD_MIN_LENGTH)
    full_name: Optional[str] = None
    is_admin: bool = False
    role_names: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_admin: bool
    mfa_enabled: bool
    sso_provider: Optional[str]
    tenant_id: Optional[str]
    roles: List[str]
    created_at: datetime.datetime


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_uri: str       # data-uri (renderable as <img src=...>)


class MfaEnableRequest(BaseModel):
    code: str         # first TOTP code proving enrollment works


class ApiKeyCreateRequest(BaseModel):
    name: str
    scopes: str = "read"
    expires_in_days: Optional[int] = None


class ApiKeyCreateResponse(BaseModel):
    id: str
    name: str
    secret: str         # SHOWN ONCE
    prefix: str
    scopes: str
    expires_at: Optional[datetime.datetime]


# ── Default seeding on first boot ──────────────────────────────────────
@router.on_event("startup")
async def _seed_defaults():
    from bradlyai.database import SessionLocal
    db = SessionLocal()
    try:
        seed_default_tenant(db)
        seed_default_roles(db)
        # Bootstrap admin user if no users exist
        if db.query(UserModel).count() == 0:
            admin = UserModel(
                id=f"usr_{secrets.token_hex(6)}",
                username="admin",
                email="admin@bradlyai.local",
                full_name="Default Admin",
                password_hash=hash_password("Admin123!ChangeMe"),
                is_active=True, is_admin=True,
                tenant_id=settings.DEFAULT_TENANT_ID,
            )
            db.add(admin)
            admin_role = db.query(RoleModel).filter(RoleModel.name == "admin").first()
            if admin_role:
                db.add(UserRoleModel(user_id=admin.id, role_id=admin_role.id,
                                     tenant_id=settings.DEFAULT_TENANT_ID, granted_by="bootstrap"))
            db.commit()
            logger.warning("Bootstrap admin user created: admin / Admin123!ChangeMe — CHANGE THIS PASSWORD.")
    finally:
        db.close()


# ── Login / Token endpoints ────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = authenticate_user(db, req.username, req.password, req.mfa_code)
    user.last_login_ip = request.client.host if request.client else None
    db.commit()
    access = create_access_token(user)
    refresh = create_refresh_token(user)
    return TokenResponse(
        access_token=access, refresh_token=refresh,
        user={"id": user.id, "username": user.username, "email": user.email,
              "is_admin": user.is_admin, "tenant_id": user.tenant_id},
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(req.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")
    user = db.query(UserModel).filter(UserModel.id == payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found / disabled")
    access = create_access_token(user)
    new_refresh = create_refresh_token(user)
    return TokenResponse(access_token=access, refresh_token=new_refresh, user={
        "id": user.id, "username": user.username, "email": user.email,
        "is_admin": user.is_admin, "tenant_id": user.tenant_id,
    })


@router.get("/me", response_model=UserResponse)
def me(user: UserModel = Depends(get_current_user), db: Session = Depends(get_db)):
    role_names = [lr.role.name for lr in user.role_links if lr.role]
    return UserResponse(
        id=user.id, username=user.username, email=user.email,
        full_name=user.full_name, is_active=user.is_active, is_admin=user.is_admin,
        mfa_enabled=user.mfa_enabled, sso_provider=user.sso_provider,
        tenant_id=user.tenant_id, roles=role_names, created_at=user.created_at,
    )


# ── User CRUD (admin only) ─────────────────────────────────────────────
@router.post("/users", response_model=UserResponse, status_code=201,
             dependencies=[Depends(require_permission("users", "write"))])
def create_user(req: CreateUserRequest, db: Session = Depends(get_db),
                actor: UserModel = Depends(get_current_user)):
    if db.query(UserModel).filter((UserModel.username == req.username) | (UserModel.email == req.email)).first():
        raise HTTPException(status_code=409, detail="Username or email already exists")
    user = UserModel(
        id=f"usr_{secrets.token_hex(6)}",
        username=req.username, email=req.email, full_name=req.full_name,
        password_hash=hash_password(req.password),
        is_admin=req.is_admin, tenant_id=req.tenant_id or settings.DEFAULT_TENANT_ID,
    )
    db.add(user)
    db.flush()
    for rname in req.role_names:
        role = db.query(RoleModel).filter(RoleModel.name == rname).first()
        if role:
            db.add(UserRoleModel(user_id=user.id, role_id=role.id, tenant_id=user.tenant_id,
                                 granted_by=actor.username))
    db.commit()
    db.refresh(user)
    return UserResponse(
        id=user.id, username=user.username, email=user.email, full_name=user.full_name,
        is_active=user.is_active, is_admin=user.is_admin, mfa_enabled=user.mfa_enabled,
        sso_provider=user.sso_provider, tenant_id=user.tenant_id, roles=[], created_at=user.created_at,
    )


@router.get("/users", response_model=List[UserResponse],
            dependencies=[Depends(require_permission("users", "read"))])
def list_users(db: Session = Depends(get_db)):
    out = []
    for u in db.query(UserModel).all():
        out.append(UserResponse(
            id=u.id, username=u.username, email=u.email, full_name=u.full_name,
            is_active=u.is_active, is_admin=u.is_admin, mfa_enabled=u.mfa_enabled,
            sso_provider=u.sso_provider, tenant_id=u.tenant_id,
            roles=[lr.role.name for lr in u.role_links if lr.role], created_at=u.created_at,
        ))
    return out


# ── MFA ────────────────────────────────────────────────────────────────
@router.post("/mfa/setup", response_model=MfaSetupResponse,
             dependencies=[Depends(require_permission("users", "write"))])
def mfa_setup(db: Session = Depends(get_db), user: UserModel = Depends(get_current_user)):
    import pyotp, qrcode, io, base64
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="BradlyAI")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    return MfaSetupResponse(secret=secret, otpauth_url=uri, qr_uri=qr_uri)


@router.post("/mfa/enable",
             dependencies=[Depends(require_permission("users", "write"))])
def mfa_enable(req: MfaEnableRequest, db: Session = Depends(get_db),
               user: UserModel = Depends(get_current_user)):
    import pyotp
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="Call /mfa/setup first")
    if not pyotp.TOTP(user.mfa_secret).verify(req.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    user.mfa_enabled = True
    db.commit()
    return {"status": "ok", "mfa_enabled": True}


@router.post("/mfa/disable",
             dependencies=[Depends(require_permission("users", "write"))])
def mfa_disable(db: Session = Depends(get_db),
                user: UserModel = Depends(get_current_user)):
    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit()
    return {"status": "ok", "mfa_enabled": False}


# ── API Keys ───────────────────────────────────────────────────────────
@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=201,
             dependencies=[Depends(require_permission("apikeys", "write"))])
def create_api_key(req: ApiKeyCreateRequest, db: Session = Depends(get_db),
                   user: UserModel = Depends(get_current_user)):
    key_id, plaintext, key_hash = ApiKeyModel.generate()
    expires_at = (datetime.datetime.now(datetime.timezone.utc) +
                  datetime.timedelta(days=req.expires_in_days)) if req.expires_in_days else None
    row = ApiKeyModel(
        id=key_id, name=req.name, key_hash=key_hash,
        prefix=plaintext[:12],                       # e.g. "brd_aBcDeFgH"
        scopes=req.scopes, owner_user_id=user.id,
        tenant_id=user.tenant_id, expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    return ApiKeyCreateResponse(
        id=row.id, name=row.name, secret=plaintext, prefix=row.prefix,
        scopes=row.scopes, expires_at=row.expires_at,
    )


@router.get("/api-keys",
            dependencies=[Depends(require_permission("apikeys", "read"))])
def list_api_keys(db: Session = Depends(get_db)):
    return [{
        "id": k.id, "name": k.name, "prefix": k.prefix, "scopes": k.scopes,
        "is_active": k.is_active, "last_used_at": k.last_used_at,
        "expires_at": k.expires_at, "created_at": k.created_at,
    } for k in db.query(ApiKeyModel).all()]


@router.delete("/api-keys/{key_id}",
               dependencies=[Depends(require_permission("apikeys", "write"))])
def revoke_api_key(key_id: str, db: Session = Depends(get_db)):
    row = db.query(ApiKeyModel).filter(ApiKeyModel.id == key_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")
    row.is_active = False
    db.commit()
    return {"status": "ok"}


# ── SSO — OIDC ─────────────────────────────────────────────────────────
@router.get("/sso/oidc/login")
def sso_oidc_login():
    if not settings.SSO_OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC SSO is not enabled")
    client = OIDCClient()
    state = secrets.token_urlsafe(16)
    code_verifier = secrets.token_urlsafe(32)
    # In a production app you'd persist (state, code_verifier) keyed by cookie.
    # For demo we sign them into a token the callback can re-present.
    verifier_payload = f"{state}.{code_verifier}"
    return {
        "authorization_url": client.authorization_url(state, code_verifier),
        "state": state,
        "verifier_token": verifier_payload,    # echo back on callback
    }


@router.post("/sso/oidc/callback")
async def sso_oidc_callback(request: Request, db: Session = Depends(get_db)):
    if not settings.SSO_OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC SSO is not enabled")
    body = await request.json()
    code = body.get("code")
    verifier_token = body.get("verifier_token", "")
    if not code or "." not in verifier_token:
        raise HTTPException(status_code=400, detail="Missing code or verifier")
    _, code_verifier = verifier_token.split(".", 1)
    client = OIDCClient()
    result = await client.exchange_code(code, code_verifier)
    claims = result["claims"]
    sub = claims.get("sub")
    email = claims.get("email", "")
    if not sub:
        raise HTTPException(status_code=400, detail="No 'sub' claim from IdP")

    user = db.query(UserModel).filter(
        (UserModel.sso_provider == "oidc") & (UserModel.sso_subject == sub)
    ).first()
    if user is None:
        # JIT provisioning
        username = email.split("@")[0] if email else sub
        user = UserModel(
            id=f"usr_{secrets.token_hex(6)}", username=username, email=email,
            password_hash=None, is_active=True, is_admin=False,
            sso_provider="oidc", sso_subject=sub,
            tenant_id=settings.DEFAULT_TENANT_ID,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return {
        "access_token": create_access_token(user),
        "refresh_token": create_refresh_token(user),
        "user": {"id": user.id, "username": user.username, "email": user.email,
                 "is_admin": user.is_admin, "tenant_id": user.tenant_id},
    }


# ── SSO — SAML (metadata + ACS) ────────────────────────────────────────
@router.get("/sso/saml/metadata")
def sso_saml_metadata():
    if not settings.SSO_SAML_ENABLED:
        raise HTTPException(status_code=404, detail="SAML SSO is not enabled")
    from bradlyai.services.sso import SAMLClient
    return SAMLClient().metadata()


@router.post("/sso/saml/acs")
async def sso_saml_acs(request: Request, db: Session = Depends(get_db)):
    """SAML Assertion Consumer Service — stub that accepts a SAMLResponse.

    Real deployments wire this up with python3-saml's request/response objects.
    """
    if not settings.SSO_SAML_ENABLED:
        raise HTTPException(status_code=404, detail="SAML SSO is not enabled")
    form = await request.form()
    saml_response = form.get("SAMLResponse")
    if not saml_response:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse")
    # In production: validate SAMLResponse signature, parse NameID + attributes,
    # JIT-provision user, return JWT.
    return {"status": "received", "detail": "Configure python3-saml for full ACS handling"}
