"""Tenant service — multi-tenancy helpers."""
from typing import Optional
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.models.tenant import TenantModel


def get_tenant_for_user(db: Session, user_tenant_id: Optional[str]) -> TenantModel:
    """Resolve the active TenantModel for a user. Falls back to default."""
    tid = user_tenant_id or settings.DEFAULT_TENANT_ID
    tenant = db.query(TenantModel).filter(TenantModel.id == tid).first()
    if tenant is None:
        tenant = TenantModel(id=tid, name=tid, is_active=True)
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
    return tenant


def seed_default_tenant(db: Session) -> None:
    """Ensure the default tenant exists on first boot."""
    existing = db.query(TenantModel).filter(TenantModel.id == settings.DEFAULT_TENANT_ID).first()
    if existing:
        return
    db.add(TenantModel(id=settings.DEFAULT_TENANT_ID, name=settings.DEFAULT_TENANT_NAME,
                       is_active=True, description="Auto-created default tenant"))
    db.commit()
