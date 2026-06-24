"""Playbook engine models — definitions + run history."""
import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey, Index, Boolean
from sqlalchemy.orm import relationship
from bradlyai.database import Base


class PlaybookModel(Base):
    __tablename__ = "playbooks"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)
    version = Column(String, default="1.0", nullable=False)
    trigger = Column(String, nullable=True, index=True)  # severity / alert_type / mitre / signal
    severity_filter = Column(String, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)
    is_builtin = Column(Boolean, default=False, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    # Steps as JSON — declarative playbook DAG
    steps_json = Column(JSON, nullable=False)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc),
                        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))


class PlaybookRunModel(Base):
    __tablename__ = "playbook_runs"
    id = Column(String, primary_key=True, index=True)
    playbook_id = Column(String, ForeignKey("playbooks.id"), index=True, nullable=False)
    case_id = Column(String, ForeignKey("cases.id"), index=True, nullable=True)
    alert_id = Column(String, nullable=True, index=True)
    status = Column(String, default="RUNNING", index=True)  # RUNNING / AWAITING_APPROVAL / COMPLETED / FAILED / CANCELLED
    current_step = Column(String, nullable=True)
    state_json = Column(JSON, nullable=True)              # variable bindings
    history_json = Column(JSON, nullable=True)            # step results history
    triggered_by = Column(String, nullable=True)
    started_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)

    __table_args__ = (
        Index("ix_pbruns_status_tenant", "status", "tenant_id"),
    )
