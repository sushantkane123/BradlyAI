"""API keys for service-to-service auth (e.g. SIEM webhooks)."""
import datetime
import hashlib
import secrets
from sqlalchemy import Column, String, DateTime, Boolean, Integer
from bradlyai.database import Base


class ApiKeyModel(Base):
    __tablename__ = "api_keys"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)                       # human-readable label
    key_hash = Column(String, unique=True, index=True, nullable=False)  # sha256 of secret
    prefix = Column(String, nullable=False, index=True)         # first 8 chars — for lookup
    owner_user_id = Column(String, nullable=True, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    scopes = Column(String, nullable=False, default="read")     # csv: "read,write,ingest,admin"
    is_active = Column(Boolean, default=True, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    @staticmethod
    def generate(prefix: str = "brd") -> tuple[str, str, str]:
        """Returns (key_id, plaintext_secret, key_hash). The plaintext is shown ONCE."""
        raw = secrets.token_urlsafe(32)
        secret = f"{prefix}_{raw}"
        key_id = f"{prefix}_{secrets.token_hex(8)}"
        return key_id, secret, hashlib.sha256(secret.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()
