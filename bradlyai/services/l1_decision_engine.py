"""Optimized BradlyAI L1 Decision Engine — highly concurrent and thread-safe.

Gains:
- Async Concurrency: Run all signal evaluations concurrently using asyncio.gather.
- Event Loop Protection: Uses asyncio.to_thread to run blocking CPU/DB-bound synchronous signal 
  checks in the background thread pool, preventing FastAPI server latency spikes.
"""

import logging
import asyncio
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

# Import the existing models and structures from BradlyAI
from bradlyai.services.fp_detector import fp_detector, Signal
from bradlyai.services.frequency_analyzer import frequency_analyzer
from bradlyai.services.whitelist import whitelist_service
from bradlyai.services.llm_classifier import llm_classifier
from bradlyai.services.historical_check import historical_check

logger = logging.getLogger("bradlyai.l1_engine_optimized")

@dataclass
class Decision:
    alert_id: str
    alert_signature: str
    decision: str  # CLOSE / ESCALATE / SHADOW_CLOSE
    confidence: float  # 0.0 - 1.0
    reason: str
    primary_signal: str
    signals: List[Dict[str, Any]] = field(default_factory=list)
    mode: str = "active"  # active / shadow
    timestamp: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signals"] = [s if isinstance(s, dict) else asdict(s) for s in self.signals]
        return d

class L1DecisionEngineOptimized:
    def __init__(self, close_threshold: float = None):
        if close_threshold is None:
            try:
                from bradlyai.config import settings
                close_threshold = settings.AUTO_CONTAINMENT_THRESHOLD
            except Exception:
                close_threshold = 0.85
        self.close_threshold = close_threshold

    def set_threshold(self, threshold: float):
        if 0.5 <= threshold <= 1.0:
            self.close_threshold = threshold
        else:
            raise ValueError("Threshold must be between 0.5 and 1.0")

    def decide_sync(self, alert, mode: str = "active") -> Decision:
        """Fast synchronous triage path (strictly excludes slow LLM checks)."""
        signals = []
        signals.append(fp_detector.check(alert))
        signals.append(frequency_analyzer.check(alert))
        
        whitelist_match = whitelist_service.check_alert(
            alert, severity=alert.severity, source=alert.source
        )
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
                name="whitelist", verdict="REAL", confidence=0.5, weight=0.40,
                reason="No whitelist match", evidence={}
            ))
            
        signals.append(historical_check.check(alert))
        return self._combine(alert, signals, mode)

    async def decide_async(self, alert, mode: str = "active") -> Decision:
        """Highly optimized async triage path.
        
        Runs all signal checks CONCURRENTLY. 
        Synchronous database and regex operations are automatically offloaded
        to threadpool workers via `asyncio.to_thread` to ensure zero blocking
        on the main async event loop.
        """
        # 1. Define concurrent background tasks
        fp_task = asyncio.to_thread(fp_detector.check, alert)
        freq_task = asyncio.to_thread(frequency_analyzer.check, alert)
        whitelist_task = asyncio.to_thread(
            whitelist_service.check_alert, alert, severity=alert.severity, source=alert.source
        )
        history_task = asyncio.to_thread(historical_check.check, alert)
        llm_task = llm_classifier.check(alert)  # Already asynchronous

        # 2. Fire all tasks concurrently
        # Latency drops from SUM(all_steps) to MAX(slowest_step) [typically the LLM API call]
        fp_sig, freq_sig, whitelist_match, hist_sig, llm_sig = await asyncio.gather(
            fp_task, freq_task, whitelist_task, history_task, llm_task
        )

        # 3. Format whitelist signal
        if whitelist_match:
            whitelist_sig = Signal(
                name="whitelist",
                verdict="FP",
                confidence=0.99,
                weight=0.40,
                reason=f"Whitelisted: {whitelist_match['name']}",
                evidence=whitelist_match,
            )
        else:
            whitelist_sig = Signal(
                name="whitelist", verdict="REAL", confidence=0.5, weight=0.40,
                reason="No whitelist match", evidence={}
            )

        signals = [fp_sig, freq_sig, whitelist_sig, hist_sig, llm_sig]
        return self._combine(alert, signals, mode)

    def _combine(self, alert, signals: List[Signal], mode: str) -> Decision:
        """Combines and balances active signal evidence to prevent neutral signal watering."""
        fp_signals = [s for s in signals if s.verdict == "FP" and s.confidence > 0.5]
        real_signals = [s for s in signals if s.verdict == "REAL" and s.confidence > 0.5]

        fp_weight_sum = sum(s.weight for s in fp_signals)
        real_weight_sum = sum(s.weight for s in real_signals)

        if fp_signals and not real_signals:
            confidence = sum(s.weight * s.confidence for s in fp_signals) / max(fp_weight_sum, 0.01)
            verdict = "CLOSE"
            primary = max(fp_signals, key=lambda s: s.weight * s.confidence)
        elif real_signals and not fp_signals:
            confidence = sum(s.weight * s.confidence for s in real_signals) / max(real_weight_sum, 0.01)
            verdict = "ESCALATE"
            primary = max(real_signals, key=lambda s: s.weight * s.confidence)
        elif fp_signals and real_signals:
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
            confidence = 0.5
            verdict = "ESCALATE"
            primary = signals[0] if signals else None

        # Enforce configurable close threshold check
        threshold_failed = False
        if verdict == "CLOSE" and confidence < self.close_threshold:
            threshold_failed = True
            verdict = "ESCALATE"

        if mode == "shadow" and verdict == "CLOSE":
            decision_str = "SHADOW_CLOSE"
        else:
            decision_str = verdict

        primary_name = primary.name if primary else "none"
        primary_reason = primary.reason if primary else "no signals"
        threshold_note = f" [threshold {self.close_threshold:.0%} not met]" if threshold_failed else ""
        
        reason = (
            f"{verdict} ({confidence:.0%}) — {primary_name}: {primary_reason}{threshold_note} "
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

# Instantiated singleton (must be named l1_engine for backwards compatibility)
l1_engine = L1DecisionEngineOptimized()
