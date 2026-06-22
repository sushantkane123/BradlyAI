"""BradlyAI Feedback — human override records used to improve the L1 Agent over time."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON
from bradlyai.database import Base


class FeedbackModel(Base):
    """Records when a human disagreed with the agent's decision.

    The feedback_loop service uses these to:
    1. Add high-confidence misses to the FP detector rules
    2. Add false alarms back to the priority queue
    3. Train the LLM classifier (if enabled)
    """
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # What decision was overridden
    audit_id = Column(Integer, index=True)                           # FK to audit_log.id
    alert_id = Column(String(64), index=True, nullable=False)
    alert_signature = Column(String(128), index=True)

    # Original agent decision
    original_decision = Column(String(16), nullable=False)           # CLOSE / ESCALATE
    original_confidence = Column(Float, nullable=False)
    original_reason = Column(Text)

    # Human verdict
    human_decision = Column(String(16), nullable=False)              # what should have happened
    human_reason = Column(Text, nullable=False)
    human_reviewer = Column(String(64))                               # who reviewed

    # Learning signal
    learned = Column(Boolean, default=False, index=True)              # has feedback_loop processed this?
    learning_action = Column(String(64))                             # what was done (e.g., "added to whitelist")
