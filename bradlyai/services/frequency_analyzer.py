"""BradlyAI Frequency Analyzer — duplicate detection via signature clustering."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.services.fp_detector import Signal

logger = logging.getLogger("bradlyai.frequency")


class FrequencyAnalyzer:
    """Signal 2: Detects duplicate alerts.

    "Same alert firing 47 times today" → high confidence FP / duplicate.
    Uses alert.signature hash + time window.
    """

    def __init__(self, window_minutes: int = 60, duplicate_threshold: int = 5):
        self.window_minutes = window_minutes
        self.duplicate_threshold = duplicate_threshold
        self.weight = 0.25

    def check(self, alert) -> Signal:
        if not getattr(alert, "signature", None):
            return Signal(
                name="frequency",
                verdict="REAL",
                confidence=0.5,
                weight=self.weight,
                reason="No signature available",
                evidence={},
            )

        db: Session = SessionLocal()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes)
            similar = db.query(AlertModel).filter(
                AlertModel.signature == alert.signature,
                AlertModel.created_at >= cutoff,
                AlertModel.id != alert.id,
            ).count()

            if similar >= self.duplicate_threshold:
                # Higher similarity = higher confidence
                confidence = min(0.99, 0.80 + (similar - self.duplicate_threshold) * 0.02)
                return Signal(
                    name="frequency",
                    verdict="FP",
                    confidence=confidence,
                    weight=self.weight,
                    reason=f"Duplicate: {similar} similar alerts in last {self.window_minutes}m",
                    evidence={"similar_count": similar, "window_minutes": self.window_minutes},
                )
            elif similar >= 2:
                return Signal(
                    name="frequency",
                    verdict="FP",
                    confidence=0.65,
                    weight=self.weight,
                    reason=f"Recurring: {similar} similar alerts in last {self.window_minutes}m",
                    evidence={"similar_count": similar},
                )
            else:
                return Signal(
                    name="frequency",
                    verdict="REAL",
                    confidence=0.4,
                    weight=self.weight,
                    reason=f"No duplicates ({similar} similar in {self.window_minutes}m)",
                    evidence={"similar_count": similar},
                )
        finally:
            db.close()


frequency_analyzer = FrequencyAnalyzer()
