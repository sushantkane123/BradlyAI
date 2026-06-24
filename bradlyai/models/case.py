"""Case (incident) management models."""
import datetime
from sqlalchemy import Column, String, DateTime, Integer, ForeignKey, Text, JSON, Index
from sqlalchemy.orm import relationship
from bradlyai.database import Base


class CaseModel(Base):
    __tablename__ = "cases"
    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, index=True)              # CRITICAL / HIGH / MEDIUM / LOW
    status = Column(String, index=True)                # OPEN / IN_PROGRESS / ESCALATED / RESOLVED / CLOSED
    priority = Column(String, default="P3", index=True)  # P1..P5
    classification = Column(String, nullable=True)     # TruePositive / FalsePositive / Benign
    tenant_id = Column(String, index=True, nullable=True)

    # SLA tracking
    sla_due_at = Column(DateTime, nullable=True)
    sla_breached = Column(Integer, default=0, nullable=False)

    # Linked ITSM / external ticket
    external_refs_json = Column(JSON, nullable=True)   # {servicenow: "INC0012345", jira: "SEC-12"}

    # Assignment
    assignee = Column(String, nullable=True, index=True)
    assignment_group = Column(String, nullable=True, index=True)

    # Playbook state
    current_playbook_id = Column(String, nullable=True)
    current_playbook_step = Column(String, nullable=True)
    pending_approval_step = Column(String, nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc),
                        onupdate=lambda: datetime.datetime.now(datetime.timezone.utc))
    closed_at = Column(DateTime, nullable=True)

    notes = relationship("CaseNoteModel", back_populates="case", cascade="all, delete-orphan")
    evidence = relationship("CaseEvidenceModel", back_populates="case", cascade="all, delete-orphan")
    alerts = relationship("AlertModel", back_populates="case", foreign_keys="AlertModel.case_id")

    __table_args__ = (
        Index("ix_cases_tenant_status", "tenant_id", "status"),
        Index("ix_cases_tenant_priority", "tenant_id", "priority"),
    )


class CaseNoteModel(Base):
    __tablename__ = "case_notes"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    author = Column(String, nullable=False)
    note = Column(Text, nullable=False)
    note_type = Column(String, default="comment", nullable=False)  # comment / status_change / system
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    case = relationship("CaseModel", back_populates="notes")


class CaseEvidenceModel(Base):
    __tablename__ = "case_evidence"
    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), index=True, nullable=False)
    evidence_type = Column(String, nullable=False, index=True)  # log / file / hash / ip / screenshot / edr_query
    value = Column(Text, nullable=False)
    source = Column(String, nullable=True)
    collected_by = Column(String, nullable=True)
    chain_of_custody_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    case = relationship("CaseModel", back_populates="evidence")
