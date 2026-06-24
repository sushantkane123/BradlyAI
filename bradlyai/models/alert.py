"""SQLAlchemy Models for Enterprise Alerts & Incident Triage."""
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Float, Index
from sqlalchemy.orm import relationship
from bradlyai.database import Base
import datetime


class AlertModel(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, index=True)
    severity = Column(String, index=True)
    title = Column(String)
    endpoint = Column(String, index=True)
    ip = Column(String)
    timestamp = Column(String)
    mitre = Column(String)
    status = Column(String)
    ai_confidence = Column(String)
    signature = Column(String, index=True)  # hash(title+endpoint+ip+user+mitre)
    closed_at = Column(DateTime, nullable=True)
    closed_reason = Column(String, nullable=True)
    closed_by = Column(String, nullable=True)  # "L1_AGENT" or analyst username
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    # ── Multi-tenancy ──
    tenant_id = Column(String, index=True, nullable=True)

    # ── Case linkage ──
    case_id = Column(String, ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)

    # ── Workflow ──
    assigned_to = Column(String, nullable=True, index=True)
    playbook_id = Column(String, nullable=True)

    storyline = relationship("AlertStorylineModel", back_populates="alert", cascade="all, delete-orphan")
    case = relationship("CaseModel", back_populates="alerts", foreign_keys=[case_id])

    __table_args__ = (
        Index("ix_alerts_tenant_status", "tenant_id", "status"),
        Index("ix_alerts_tenant_created", "tenant_id", "created_at"),
    )


class AlertStorylineModel(Base):
    __tablename__ = "alert_storylines"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, ForeignKey("alerts.id"))
    time = Column(String)
    event = Column(String)
    alert = relationship("AlertModel", back_populates="storyline")
