"""User model — local accounts + SSO-linked accounts."""
import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Index, Integer
from bradlyai.database import Base


class UserModel(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)            # NULL for SSO-only accounts
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String, nullable=True)                # TOTP secret (encrypted-at-rest recommended)
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String, nullable=True)

    # ── SSO linkage ──
    sso_provider = Column(String, nullable=True)             # "oidc" | "saml" | NULL
    sso_subject = Column(String, nullable=True, index=True)   # "sub" claim / NameID

    # ── Multi-tenancy ──
    tenant_id = Column(String, index=True, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc),
                        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        Index("ix_users_tenant_active", "tenant_id", "is_active"),
    )
