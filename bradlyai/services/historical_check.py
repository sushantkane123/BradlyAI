"""BradlyAI Historical Precedent — checks past decisions on the same signature."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.services.fp_detector import Signal

logger = logging.getLogger("bradlyai.historical")


class HistoricalCheck:
    """Signal 5: Looks at past decisions on the same alert signature.

    "Last 50 times we saw this signature, 48 were closed as FP" → high confidence FP.
    """

    def __init__(self, min_history: int = 5):
        self.min_history = min_history
        self.weight = 0.15

    def check(self, alert) -> Signal:
        if not getattr(alert, "signature", None):
            return Signal(
                name="historical",
                verdict="REAL",
                confidence=0.5,
                weight=self.weight,
                reason="No signature available",
                evidence={},
            )

        db: Session = SessionLocal()
        try:
            # Last N alerts with this signature
            past = db.query(AlertModel).filter(
                AlertModel.signature == alert.signature,
                AlertModel.id != alert.id,
            ).order_by(AlertModel.created_at.desc()).limit(50).all()

            total = len(past)
            if total < self.min_history:
                return Signal(
                    name="historical",
                    verdict="REAL",
                    confidence=0.5,
                    weight=self.weight,
                    reason=f"Insufficient history ({total} past alerts)",
                    evidence={"past_total": total},
                )

            closed_fp = sum(1 for a in past if a.status == "closed"
                            and a.closed_by == "L1_AGENT"
                            and a.closed_reason and "false" in a.closed_reason.lower())
            closed_real = sum(1 for a in past if a.status == "closed"
                              and a.closed_by and a.closed_by != "L1_AGENT")
            escalated = sum(1 for a in past if a.status not in ("closed",))

            fp_ratio = closed_fp / total

            if fp_ratio >= 0.85:
                return Signal(
                    name="historical",
                    verdict="FP",
                    confidence=min(0.95, 0.70 + fp_ratio * 0.30),
                    weight=self.weight,
                    reason=f"Historical: {closed_fp}/{total} = {fp_ratio:.0%} auto-closed as FP",
                    evidence={"fp_ratio": fp_ratio, "past_total": total, "closed_fp": closed_fp},
                )
            elif closed_real > closed_fp:
                return Signal(
                    name="historical",
                    verdict="REAL",
                    confidence=0.75,
                    weight=self.weight,
                    reason=f"Historical: {closed_real} human-closed-as-real vs {closed_fp} auto-FP",
                    evidence={"closed_real": closed_real, "closed_fp": closed_fp},
                )
            else:
                return Signal(
                    name="historical",
                    verdict="REAL",
                    confidence=0.5,
                    weight=self.weight,
                    reason=f"Mixed history: {closed_fp} FP / {closed_real} real / {escalated} open",
                    evidence={"closed_fp": closed_fp, "closed_real": closed_real, "escalated": escalated},
                )
        finally:
            db.close()


historical_check = HistoricalCheck()
