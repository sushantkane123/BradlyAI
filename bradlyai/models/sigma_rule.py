"""Sigma rule model — local copy of SigmaHQ rules for offline detection."""
import datetime
from sqlalchemy import Column, String, Text, JSON, DateTime, Boolean, Index
from bradlyai.database import Base


class SigmaRuleModel(Base):
    __tablename__ = "sigma_rules"
    id = Column(String, primary_key=True, index=True)        # UUID
    title = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)
    level = Column(String, index=True)                       # informational/low/medium/high/critical
    status = Column(String, default="experimental", index=True)  # stable/test/experimental/deprecated
    logsource_product = Column(String, index=True)           # windows, linux, aws, etc.
    logsource_category = Column(String, index=True)          # process_creation, network_connection, etc.
    logsource_service = Column(String, nullable=True)
    detection_json = Column(JSON, nullable=False)            # full Sigma detection block
    fields_json = Column(JSON, nullable=True)
    falsepositives_json = Column(JSON, nullable=True)
    references_json = Column(JSON, nullable=True)
    tags_json = Column(JSON, nullable=True)                  # MITRE tactics + techniques
    author = Column(String, nullable=True)
    date = Column(DateTime, nullable=True)
    modified = Column(DateTime, nullable=True)
    raw_yaml = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    tenant_id = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        Index("ix_sigma_logsource", "logsource_product", "logsource_category"),
        Index("ix_sigma_level_status", "level", "status"),
    )
