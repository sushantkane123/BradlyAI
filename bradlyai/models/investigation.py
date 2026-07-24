"""Persistent, evidence-backed investigations produced by the SOC investigation agent."""
from __future__ import annotations

import datetime
import secrets

from sqlalchemy import Column, DateTime, ForeignKey, Index, JSON, String, Text

from bradlyai.database import Base


def new_investigation_id() -> str:
    return f"INV-{secrets.token_hex(6).upper()}"


class InvestigationModel(Base):
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, default=new_investigation_id)
    alert_id = Column(String, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String, nullable=True, index=True)
    status = Column(String, nullable=False, default="COMPLETED", index=True)
    recommendation = Column(String, nullable=False, index=True)
    confidence = Column(String, nullable=False)
    summary = Column(Text, nullable=False)

    # Every item is serializable and includes source/provenance so a reviewer can
    # distinguish observed evidence from an agent inference.
    plan_json = Column(JSON, nullable=False, default=list)
    evidence_json = Column(JSON, nullable=False, default=list)
    hypotheses_json = Column(JSON, nullable=False, default=list)
    policy_json = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), index=True)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.datetime.now(datetime.timezone.utc),
        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc),
    )

    __table_args__ = (
        Index("ix_investigations_tenant_created", "tenant_id", "created_at"),
        Index("ix_investigations_alert_created", "alert_id", "created_at"),
    )
