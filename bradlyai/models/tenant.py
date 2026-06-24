"""Tenant model — multi-tenancy."""
import datetime
from sqlalchemy import Column, String, Boolean, DateTime, JSON
from bradlyai.database import Base


class TenantModel(Base):
    __tablename__ = "tenants"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    contact_email = Column(String, nullable=True)
    settings_json = Column(JSON, nullable=True)            # per-tenant overrides
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc),
                        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))
