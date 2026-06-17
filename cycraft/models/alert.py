"""
SQLAlchemy Models for Enterprise Alerts & Incident Triage
"""

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from cycraft.database import Base
import datetime

class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    severity = Column(String, index=True) # CRITICAL, HIGH, MEDIUM, LOW
    title = Column(String)
    endpoint = Column(String, index=True)
    ip = Column(String)
    timestamp = Column(String)
    mitre = Column(String)
    status = Column(String) # Auto-Contained, Investigating, Resolved
    ai_confidence = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    storyline = relationship("AlertStorylineModel", back_populates="alert", cascade="all, delete-orphan")

class AlertStorylineModel(Base):
    __tablename__ = "alert_storylines"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, ForeignKey("alerts.id"))
    time = Column(String)
    event = Column(String)

    alert = relationship("AlertModel", back_populates="storyline")
