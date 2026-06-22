"""BradlyAI Auto-Closer — takes action on alerts: marks CLOSED, records audit log."""
import logging
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.models.audit_log import AuditLogModel
from bradlyai.services.l1_decision_engine import Decision

logger = logging.getLogger("bradlyai.auto_closer")


class AutoCloser:
    """Applies the L1 Agent's decision: closes alerts, logs audit trail, returns results."""

    def __init__(self, agent_version: str = "1.0.0"):
        self.agent_version = agent_version

    def apply(self, decision: Decision, alert_id_from_db: Optional[str] = None) -> Dict[str, Any]:
        """Apply a decision to the alert database.

        Returns a result dict with action taken + audit log id.
        In shadow mode, the action is recorded but the alert is NOT closed.
        """
        db: Session = SessionLocal()
        try:
            audit = AuditLogModel(
                alert_id=decision.alert_id,
                alert_source=decision.signals[0].get("evidence", {}).get("entry_id", "unknown") if decision.signals else "unknown",
                alert_signature=decision.alert_signature,
                alert_title=decision.signals[0].get("evidence", {}).get("name", "") if decision.signals else "",
                alert_severity="",
                decision=decision.decision,
                confidence=decision.confidence,
                reason=decision.reason,
                primary_signal=decision.primary_signal,
                signals=decision.signals,
                signal_weights={s["name"]: s["weight"] for s in decision.signals},
                action_taken="none",
                mode=decision.mode,
                agent_version=self.agent_version,
            )

            # Find the actual alert in DB
            alert = db.query(AlertModel).filter(
                AlertModel.id == (alert_id_from_db or decision.alert_id)
            ).first()

            if decision.decision == "CLOSE" and alert:
                alert.status = "closed"
                alert.closed_at = datetime.now(timezone.utc)
                alert.closed_reason = decision.reason
                alert.closed_by = "L1_AGENT"
                audit.action_taken = "closed"
                audit.action_target = alert.id
                audit.action_result = "success"
                audit.alert_title = alert.title
                audit.alert_severity = alert.severity
                audit.alert_source = _extract_source(alert)
            elif decision.decision == "ESCALATE":
                audit.action_taken = "escalated"
                audit.action_result = "no_change"
                audit.alert_title = decision.alert_id
            elif decision.decision == "SHADOW_CLOSE":
                audit.action_taken = "shadow_no_action"
                audit.action_result = "shadow_mode"

            db.add(audit)
            db.commit()
            db.refresh(audit)

            logger.info(
                f"L1 Agent: alert={decision.alert_id} decision={decision.decision} "
                f"confidence={decision.confidence:.2%} audit_id={audit.id}"
            )

            return {
                "audit_id": audit.id,
                "alert_id": decision.alert_id,
                "decision": decision.decision,
                "confidence": decision.confidence,
                "action_taken": audit.action_taken,
                "alert_closed": audit.action_taken == "closed",
                "reason": decision.reason,
            }
        except Exception as e:
            logger.exception(f"Auto-closer failed for {decision.alert_id}: {e}")
            db.rollback()
            return {
                "alert_id": decision.alert_id,
                "decision": decision.decision,
                "error": str(e),
            }
        finally:
            db.close()


def _extract_source(alert: AlertModel) -> str:
    """Guess the source of an existing alert based on id prefix."""
    aid = alert.id or ""
    if aid.startswith("SPL-"):
        return "splunk"
    if aid.startswith("WAZ-"):
        return "wazuh"
    if aid.startswith("JIRA-"):
        return "jira"
    if aid.startswith("ALT-"):
        return "bradlyai"
    return "unknown"


auto_closer = AutoCloser()
