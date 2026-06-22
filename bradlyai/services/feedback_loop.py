"""BradlyAI Feedback Loop — learn from human overrides."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.models.feedback import FeedbackModel
from bradlyai.models.whitelist_entry import WhitelistEntryModel
from bradlyai.models.audit_log import AuditLogModel

logger = logging.getLogger("bradlyai.feedback_loop")


class FeedbackLoop:
    """Records when humans disagree with the agent, and learns from it.

    On override:
    - If agent closed but human says REAL → re-open alert, optionally add IP/user to whitelist negation
    - If agent escalated but human says FP → optionally add to whitelist

    The "learned" flag prevents reprocessing the same feedback.
    """

    def reopen_alert(self, alert_id: str, reviewer: str, reason: str) -> Dict[str, Any]:
        """Reopen an alert the agent closed. Records the override for learning."""
        db: Session = SessionLocal()
        try:
            alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if not alert:
                return {"error": f"Alert {alert_id} not found"}

            was_closed_by_agent = alert.closed_by == "L1_AGENT"

            if not was_closed_by_agent:
                return {"warning": f"Alert {alert_id} was not closed by L1 Agent (closed_by={alert.closed_by})"}

            # Find the most recent audit entry for this alert
            audit = db.query(AuditLogModel).filter(
                AuditLogModel.alert_id == alert_id
            ).order_by(AuditLogModel.timestamp.desc()).first()

            # Reopen
            alert.status = "open"
            alert.closed_at = None
            alert.closed_reason = None
            alert.closed_by = None

            # Record override on audit log
            if audit:
                audit.overridden_at = datetime.now(timezone.utc)
                audit.overridden_by = reviewer
                audit.override_reason = reason

            # Record feedback
            feedback = FeedbackModel(
                audit_id=audit.id if audit else None,
                alert_id=alert_id,
                alert_signature=alert.signature or "",
                original_decision="CLOSE",
                original_confidence=audit.confidence if audit else 0.0,
                original_reason=audit.reason if audit else "",
                human_decision="REAL",
                human_reason=reason,
                human_reviewer=reviewer,
            )
            db.add(feedback)
            db.commit()

            logger.info(f"Alert {alert_id} reopened by {reviewer}: {reason}")

            return {
                "alert_id": alert_id,
                "status": "reopened",
                "feedback_id": feedback.id,
                "audit_id": audit.id if audit else None,
            }
        finally:
            db.close()

    def confirm_fp(self, alert_id: str, reviewer: str, note: str = "") -> Dict[str, Any]:
        """Human confirms the agent's FP closure was correct. Pure positive signal."""
        db: Session = SessionLocal()
        try:
            alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if not alert:
                return {"error": f"Alert {alert_id} not found"}
            audit = db.query(AuditLogModel).filter(
                AuditLogModel.alert_id == alert_id
            ).order_by(AuditLogModel.timestamp.desc()).first()

            feedback = FeedbackModel(
                audit_id=audit.id if audit else None,
                alert_id=alert_id,
                alert_signature=alert.signature or "",
                original_decision="CLOSE",
                original_confidence=audit.confidence if audit else 0.0,
                original_reason=audit.reason if audit else "",
                human_decision="FP",
                human_reason=note or "Confirmed correct auto-close",
                human_reviewer=reviewer,
            )
            db.add(feedback)
            db.commit()
            return {"alert_id": alert_id, "feedback_id": feedback.id, "confirmed": True}
        finally:
            db.close()

    def process_unprocessed_feedback(self) -> Dict[str, Any]:
        """Process unprocessed feedback records — turn them into whitelist entries or signals.

        Run this periodically (cron) to improve the agent.
        """
        db: Session = SessionLocal()
        try:
            pending = db.query(FeedbackModel).filter(
                FeedbackModel.learned == False,
                FeedbackModel.human_decision == "REAL",   # agent was wrong, missed a real threat
            ).all()

            learned_count = 0
            for fb in pending:
                if not fb.alert_signature:
                    continue
                alert = db.query(AlertModel).filter(AlertModel.id == fb.alert_id).first()
                if not alert:
                    continue
                # Skip if there's already a whitelist entry for this signature negation
                # For now: mark as learned; future enhancement could add to a "known FP negatives" list
                fb.learned = True
                fb.learning_action = "logged_for_review"
                learned_count += 1

            db.commit()
            return {"processed": learned_count}
        finally:
            db.close()


feedback_loop = FeedbackLoop()
