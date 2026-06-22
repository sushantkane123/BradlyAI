"""BradlyAI L1 Decision Engine — combines 5 signals to produce a final verdict.

This is the brain of the L1 SOC Agent. It evaluates each incoming alert against:
  1. Rule-based FP detector (regex patterns of known-benign activity)
  2. Frequency analyzer (duplicate detection)
  3. Whitelist matcher (allow-listed sources/users/processes)
  4. LLM classifier (semantic understanding via Groq/OpenAI)
  5. Historical precedent (past decisions on same signature)

Each signal votes FP or REAL with a confidence. Signals are weighted and combined.
The final verdict is CLOSE (auto-close) or ESCALATE (send to human).
"""
import logging
import asyncio
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from bradlyai.services.fp_detector import fp_detector, Signal
from bradlyai.services.frequency_analyzer import frequency_analyzer
from bradlyai.services.whitelist import whitelist_service
from bradlyai.services.llm_classifier import llm_classifier
from bradlyai.services.historical_check import historical_check

logger = logging.getLogger("bradlyai.l1_engine")


@dataclass
class Decision:
    """The final verdict from the L1 Decision Engine."""
    alert_id: str
    alert_signature: str
    decision: str                # CLOSE / ESCALATE / SHADOW_CLOSE
    confidence: float            # 0.0 - 1.0
    reason: str
    primary_signal: str          # which signal tipped the scale
    signals: List[Dict[str, Any]] = field(default_factory=list)
    mode: str = "active"         # active / shadow
    timestamp: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signals"] = [s if isinstance(s, dict) else asdict(s) for s in self.signals]
        return d


class L1DecisionEngine:
    """Combines 5 weighted signals into a final CLOSE/ESCALATE decision."""

    def __init__(self, close_threshold: float = 0.85):
        self.close_threshold = close_threshold

    def set_threshold(self, threshold: float):
        if 0.5 <= threshold <= 1.0:
            self.close_threshold = threshold
        else:
            raise ValueError("Threshold must be between 0.5 and 1.0")

    def decide_sync(self, alert, mode: str = "active") -> Decision:
        """Synchronous decision (no LLM). Faster, used for high-throughput queues."""
        signals = []
        signals.append(fp_detector.check(alert))
        signals.append(frequency_analyzer.check(alert))
        whitelist_match = whitelist_service.check_alert(alert,
                                                        severity=alert.severity,
                                                        source=alert.source)
        if whitelist_match:
            signals.append(Signal(
                name="whitelist",
                verdict="FP",
                confidence=0.99,
                weight=0.40,                # strong signal
                reason=f"Whitelisted: {whitelist_match['name']}",
                evidence=whitelist_match,
            ))
        else:
            signals.append(Signal(
                name="whitelist",
                verdict="REAL",
                confidence=0.5,
                weight=0.40,
                reason="No whitelist match",
                evidence={},
            ))
        signals.append(historical_check.check(alert))
        return self._combine(alert, signals, mode)

    async def decide_async(self, alert, mode: str = "active") -> Decision:
        """Async decision with LLM. Slower but more accurate."""
        signals = []
        signals.append(fp_detector.check(alert))
        signals.append(frequency_analyzer.check(alert))
        whitelist_match = whitelist_service.check_alert(alert,
                                                        severity=alert.severity,
                                                        source=alert.source)
        if whitelist_match:
            signals.append(Signal(
                name="whitelist",
                verdict="FP",
                confidence=0.99,
                weight=0.40,
                reason=f"Whitelisted: {whitelist_match['name']}",
                evidence=whitelist_match,
            ))
        else:
            signals.append(Signal(
                name="whitelist",
                verdict="REAL",
                confidence=0.5,
                weight=0.40,
                reason="No whitelist match",
                evidence={},
            ))
        signals.append(historical_check.check(alert))
        signals.append(await llm_classifier.check(alert))
        return self._combine(alert, signals, mode)

    def _combine(self, alert, signals: List[Signal], mode: str) -> Decision:
        """Combine signals into final decision.

        Logic: only signals with positive evidence vote. Neutral / "no opinion"
        signals are excluded from the calculation. Otherwise a single weak FP
        signal gets outweighed by multiple neutral REAL signals.

        FP_confidence = sum(weight * confidence) for FP signals / sum(weight) for FP signals
        REAL_confidence = same for REAL signals
        Compare FP_confidence vs REAL_confidence. Whichever is higher wins.
        If only one side voted, that side wins with full confidence.
        If neither voted (all neutral) → ESCALATE (conservative default).
        """
        fp_signals = [s for s in signals if s.verdict == "FP" and s.confidence > 0.5]
        real_signals = [s for s in signals if s.verdict == "REAL" and s.confidence > 0.5]

        fp_weight_sum = sum(s.weight for s in fp_signals)
        real_weight_sum = sum(s.weight for s in real_signals)

        if fp_signals and not real_signals:
            # Only FP signals voted
            confidence = sum(s.weight * s.confidence for s in fp_signals) / max(fp_weight_sum, 0.01)
            verdict = "CLOSE"
            primary = max(fp_signals, key=lambda s: s.weight * s.confidence)
        elif real_signals and not fp_signals:
            # Only REAL signals voted
            confidence = sum(s.weight * s.confidence for s in real_signals) / max(real_weight_sum, 0.01)
            verdict = "ESCALATE"
            primary = max(real_signals, key=lambda s: s.weight * s.confidence)
        elif fp_signals and real_signals:
            # Both sides voted — compare
            fp_score = sum(s.weight * s.confidence for s in fp_signals)
            real_score = sum(s.weight * s.confidence for s in real_signals)
            if fp_score > real_score:
                confidence = fp_score / (fp_score + real_score)
                verdict = "CLOSE"
                primary = max(fp_signals, key=lambda s: s.weight * s.confidence)
            else:
                confidence = real_score / (fp_score + real_score)
                verdict = "ESCALATE"
                primary = max(real_signals, key=lambda s: s.weight * s.confidence)
        else:
            # Nobody has evidence → conservative default
            confidence = 0.5
            verdict = "ESCALATE"
            primary = signals[0] if signals else None

        if mode == "shadow" and verdict == "CLOSE":
            decision_str = "SHADOW_CLOSE"
        else:
            decision_str = verdict

        primary_name = primary.name if primary else "none"
        primary_reason = primary.reason if primary else "no signals"
        reason = (
            f"{verdict} ({confidence:.0%}) — {primary_name}: {primary_reason} "
            f"[{', '.join(f'{s.name}={s.verdict}@{s.confidence:.0%}' for s in signals)}]"
        )

        return Decision(
            alert_id=alert.id,
            alert_signature=getattr(alert, "signature", ""),
            decision=decision_str,
            confidence=round(confidence, 4),
            reason=reason,
            primary_signal=primary_name,
            signals=[asdict(s) for s in signals],
            mode=mode,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


l1_engine = L1DecisionEngine()
