"""BradlyAI Audit Log — every L1 Agent decision is recorded for compliance & review."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, JSON
from bradlyai.database import Base


class AuditLogModel(Base):
    """Immutable record of every decision the L1 Agent makes.

    Never updated after creation — append-only for compliance.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # What alert was decided on
    alert_id = Column(String(64), index=True, nullable=False)
    alert_source = Column(String(32), index=True, nullable=False)   # splunk/wazuh/jira
    alert_signature = Column(String(128), index=True)               # for duplicate correlation
    alert_title = Column(String(512))
    alert_severity = Column(String(16), index=True)

    # What the agent decided
    decision = Column(String(16), index=True, nullable=False)        # CLOSE / ESCALATE / SHADOW_CLOSE
    confidence = Column(Float, nullable=False)                       # 0.0 - 1.0
    reason = Column(Text, nullable=False)                            # human-readable summary
    primary_signal = Column(String(64))                              # which signal was dominant

    # The 5 signals (for replay/debug)
    signals = Column(JSON, nullable=False)                           # full signal breakdown
    signal_weights = Column(JSON, nullable=False)                    # weights used

    # Action taken (or not, in shadow mode)
    action_taken = Column(String(32))                                # closed/escalated/no_action
    action_target = Column(String(64))                               # alert id / ticket id
    action_result = Column(String(32))                               # success/failure/n/a

    # Mode context
    mode = Column(String(16), nullable=False)                       # active / shadow
    agent_version = Column(String(16))                               # for tracking config changes

    # Human override (set later if human disagrees)
    overridden_at = Column(DateTime, nullable=True)
    overridden_by = Column(String(64), nullable=True)
    override_reason = Column(Text, nullable=True)
