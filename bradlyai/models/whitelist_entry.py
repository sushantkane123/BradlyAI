"""BradlyAI Whitelist — known-good sources, users, processes that should not generate alerts."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, JSON
from bradlyai.database import Base


class WhitelistEntryModel(Base):
    """An allow-list rule that suppresses alerts matching specific criteria.

    Examples:
    - Internal vulnerability scanner (10.0.0.50)
    - Service account used by monitoring (svc_monitoring)
    - Microsoft update process (TiWorker.exe)
    - Approved after-hours work window
    """
    __tablename__ = "whitelist_entries"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    # Classification
    entry_type = Column(String(32), index=True, nullable=False)
    # Allowed types: source_ip, user, process, domain, asset, alert_signature, time_window

    # Match criteria (at least one must match)
    match_value = Column(String(512), nullable=False)                # the IP / user / process name
    match_field = Column(String(64))                                 # which field in alert to match against
    match_pattern = Column(String(32), default="exact")              # exact / regex / wildcard

    # Scope
    severity_filter = Column(JSON)                                   # applies only to these severities, null = all
    source_filter = Column(JSON)                                     # applies only to these sources, null = all
    ttl_seconds = Column(Integer, nullable=True)                     # auto-expire after N seconds, null = permanent

    # Audit
    created_by = Column(String(64), default="system")
    enabled = Column(Boolean, default=True, index=True)
    hit_count = Column(Integer, default=0)                           # how many alerts this rule suppressed
    last_hit_at = Column(DateTime, nullable=True)

    # Human-readable
    name = Column(String(128))                                       # e.g., "Internal Nessus scanner"
    description = Column(Text)                                       # why this is whitelisted
