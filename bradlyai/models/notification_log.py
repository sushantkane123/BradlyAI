"""Notification audit log."""
import datetime
from sqlalchemy import Column, String, DateTime, JSON, Integer, Index
from bradlyai.database import Base


class NotificationLogModel(Base):
    __tablename__ = "notification_log"
    id = Column(Integer, primary_key=True, index=True)
    channel = Column(String, index=True, nullable=False)
    target = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    body = Column(String, nullable=True)
    success = Column(String, nullable=False)        # store "true"/"false" for SQLite compat
    detail = Column(String, nullable=True)
    triggered_by = Column(String, nullable=True)
    tenant_id = Column(String, index=True, nullable=True)
    payload_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        Index("ix_notiflog_tenant_channel", "tenant_id", "channel"),
    )
