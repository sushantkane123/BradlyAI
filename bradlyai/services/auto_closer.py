"""BradlyAI Auto-Closer — takes action on alerts: marks CLOSED, records audit log.

Also calls Wazuh Manager API to close alerts in the Wazuh SIEM when:
  - Source is wazuh
  - Decision is CLOSE
  - Wazuh integration is enabled (WAZUH_ENABLED=true)
  - Dry-run mode is disabled or in dry-run (logs only)

Safety:
  - Default WAZUH_ENABLED=false (no Wazuh API calls)
  - Default WAZUH_DRY_RUN=true (logs what would happen, doesn't do it)
  - Archive is reversible in Wazuh UI
"""
import logging
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.models.audit_log import AuditLogModel
from bradlyai.services.l1_decision_engine import Decision
from bradlyai.services.wazuh_api import wazuh_api

logger = logging.getLogger("bradlyai.auto_closer")


class AutoCloser:
    """Applies the L1 Agent's decision: closes alerts, logs audit trail, calls Wazuh API."""

    def __init__(self, agent_version: str = "1.0.0"):
        self.agent_version = agent_version

    def apply(self, decision: Decision, alert_id_from_db: Optional[str] = None) -> Dict[str, Any]:
        """Apply a decision to the alert database.

        Returns a result dict with action taken + audit log id.
        In shadow mode, the action is recorded but the alert is NOT closed.
        For wazuh alerts, also calls Wazuh Manager API to close there.
        """
        db: Session = SessionLocal()
        try:
            alert_source = _extract_source(decision.alert_id)

            audit = AuditLogModel(
                alert_id=decision.alert_id,
                alert_source=alert_source,
                alert_signature=decision.alert_signature,
                alert_title="",
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

            # Find the actual alert in local DB
            alert = db.query(AlertModel).filter(
                AlertModel.id == (alert_id_from_db or decision.alert_id)
            ).first()
            # Real-event ingestion stores the canonical source on AlertModel; prefer
            # it over legacy ID-prefix inference so every audit row is attributable.
            if alert:
                if getattr(alert, "source", None):
                    alert_source = alert.source
                    audit.alert_source = alert_source
                audit.alert_title = alert.title
                audit.alert_severity = alert.severity

            if decision.decision == "CLOSE" and alert:
                alert.status = "closed"
                alert.closed_at = datetime.now(timezone.utc)
                alert.closed_reason = decision.reason
                alert.closed_by = "L1_AGENT"
                audit.alert_title = alert.title
                audit.alert_severity = alert.severity
                audit.alert_source = alert_source

                # Close in Wazuh if source is wazuh
                wazuh_result = None
                if alert_source == "wazuh":
                    wazuh_result = self._close_in_wazuh(decision.alert_id, decision.reason)
                    audit.action_taken = "closed_locally_and_wazuh" if (wazuh_result and wazuh_result.get("success")) else "closed_locally_wazuh_failed"
                    audit.action_result = json.dumps(wazuh_result) if wazuh_result else "no_wazuh_call"
                else:
                    audit.action_taken = "closed"
                    audit.action_result = "success"

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

            # If Wazuh result exists, store it on the audit (need to re-fetch since commit happened)
            if decision.decision == "CLOSE" and alert_source == "wazuh":
                audit.action_result = json.dumps(wazuh_result) if wazuh_result else "no_wazuh_call"
                if wazuh_result and wazuh_result.get("success"):
                    audit.action_taken = "closed_locally_and_wazuh"
                elif wazuh_result:
                    audit.action_taken = "closed_locally_wazuh_failed"
                db.commit()

            logger.info(
                f"L1 Agent: alert={decision.alert_id} source={alert_source} "
                f"decision={decision.decision} confidence={decision.confidence:.2%} "
                f"audit_id={audit.id}"
            )

            return {
                "audit_id": audit.id,
                "alert_id": decision.alert_id,
                "decision": decision.decision,
                "confidence": decision.confidence,
                "action_taken": audit.action_taken,
                "alert_closed": audit.action_taken and audit.action_taken.startswith("closed"),
                "reason": decision.reason,
                "wazuh_result": wazuh_result if decision.decision == "CLOSE" and alert_source == "wazuh" else None,
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

    def _close_in_wazuh(self, alert_id: str, reason: str) -> Optional[Dict[str, Any]]:
        """Call Wazuh Manager API to close the alert there too. Safe by default."""
        try:
            # Strip the "WAZ-" prefix we add locally — Wazuh uses numeric IDs
            wazuh_id = alert_id
            if wazuh_id.startswith("WAZ-"):
                wazuh_id = wazuh_id[4:]
            result = wazuh_api.close_alert(
                alert_id=wazuh_id,
                reason=reason,
            )
            logger.info(f"Wazuh close result for {alert_id}: success={result.get('success')} dry_run={result.get('dry_run')}")
            return result
        except Exception as e:
            logger.error(f"Wazuh close failed for {alert_id}: {e}")
            return {"success": False, "error": str(e)}


def _extract_source(alert_id: str) -> str:
    """Guess the source of an alert based on id prefix."""
    aid = alert_id or ""
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
