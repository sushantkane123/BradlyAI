"""BradlyAI Historical Precedent — checks past decisions using fuzzy title semantic similarity.

Gains:
- Fuzzy/Semantic Generalization: If an exact signature lacks history, it performs a Jaccard 
  token similarity check across past alerts, matching on similar behavioral descriptions.
- Enhanced Accuracy: Reduces false escalations on un-profiled alert variations.
"""

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Set
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.services.fp_detector import Signal

logger = logging.getLogger("bradlyai.historical_optimized")

class HistoricalCheckOptimized:
    def __init__(self, min_history: int = 5):
        self.min_history = min_history
        self.weight = 0.15

    def _get_tokens(self, text: str) -> Set[str]:
        if not text:
            return set()
        # Normalize text and split into unique alphabetic tokens
        return set(re.sub(r"[^a-zA-Z\s]", "", text).lower().split())

    def _calculate_similarity(self, tokens_a: Set[str], tokens_b: Set[str]) -> float:
        if not tokens_a or not tokens_b:
            return 0.0
        return len(tokens_a.intersection(tokens_b)) / len(tokens_a.union(tokens_b))

    def check(self, alert) -> Signal:
        if not getattr(alert, "signature", None):
            return Signal(
                name="historical", verdict="REAL", confidence=0.5, weight=self.weight,
                reason="No signature available", evidence={}
            )

        db: Session = SessionLocal()
        try:
            # 1. First path: Attempt exact signature matching
            past = db.query(AlertModel).filter(
                AlertModel.signature == alert.signature,
                AlertModel.id != alert.id,
            ).order_by(AlertModel.created_at.desc()).limit(50).all()

            matched_by_semantic = False
            total = len(past)

            # 2. Semantic/Fuzzy Fallback: If exact matches are insufficient, check title similarity
            if total < self.min_history:
                logger.info(f"Exact signature match insufficient ({total} records). Falling back to fuzzy title matching...")
                
                # Fetch recent historical logs to find fuzzy sibling alerts
                recent_alerts = db.query(AlertModel).filter(
                    AlertModel.id != alert.id
                ).order_by(AlertModel.created_at.desc()).limit(150).all()
                
                alert_tokens = self._get_tokens(alert.title)
                fuzzy_past = []
                
                for past_alert in recent_alerts:
                    past_tokens = self._get_tokens(past_alert.title)
                    similarity = self._calculate_similarity(alert_tokens, past_tokens)
                    
                    if similarity >= 0.65:  # High similarity threshold
                        fuzzy_past.append(past_alert)
                
                if len(fuzzy_past) >= self.min_history:
                    past = fuzzy_past[:50]
                    total = len(past)
                    matched_by_semantic = True
                    logger.info(f"Fuzzy fallback match succeeded: found {total} semantically similar alerts.")

            if total < self.min_history:
                return Signal(
                    name="historical", verdict="REAL", confidence=0.5, weight=self.weight,
                    reason=f"Insufficient history ({total} past alerts found)",
                    evidence={"past_total": total},
                )

            # Analyze the historical distribution of closed vs escalated states
            closed_fp = sum(1 for a in past if a.status == "closed" 
                            and a.closed_by == "L1_AGENT" 
                            and a.closed_reason and "false" in a.closed_reason.lower())
            closed_real = sum(1 for a in past if a.status == "closed" 
                              and a.closed_by and a.closed_by != "L1_AGENT")
            escalated = sum(1 for a in past if a.status not in ("closed",))

            fp_ratio = closed_fp / total
            method_type = "Fuzzy-Semantic" if matched_by_semantic else "Exact"

            if fp_ratio >= 0.85:
                return Signal(
                    name="historical",
                    verdict="FP",
                    confidence=min(0.95, 0.70 + fp_ratio * 0.30),
                    weight=self.weight,
                    reason=f"Historical ({method_type}): {closed_fp}/{total} = {fp_ratio:.0%} auto-closed as FP",
                    evidence={"fp_ratio": fp_ratio, "past_total": total, "closed_fp": closed_fp, "semantic_match": matched_by_semantic},
                )
            elif closed_real > closed_fp:
                return Signal(
                    name="historical",
                    verdict="REAL",
                    confidence=0.75,
                    weight=self.weight,
                    reason=f"Historical ({method_type}): {closed_real} human-closed-as-real vs {closed_fp} auto-FP",
                    evidence={"closed_real": closed_real, "closed_fp": closed_fp, "semantic_match": matched_by_semantic},
                )
            else:
                return Signal(
                    name="historical",
                    verdict="REAL",
                    confidence=0.5,
                    weight=self.weight,
                    reason=f"Mixed history ({method_type}): {closed_fp} FP / {closed_real} real / {escalated} open",
                    evidence={"closed_fp": closed_fp, "closed_real": closed_real, "escalated": escalated, "semantic_match": matched_by_semantic},
                )
        finally:
            db.close()

# Singleton Instantiation
historical_check = HistoricalCheckOptimized()
