"""BradlyAI FP Detector — rule-based false-positive detection."""
import re
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

logger = logging.getLogger("bradlyai.fp_detector")


@dataclass
class Signal:
    """One signal in the L1 Agent's decision."""
    name: str
    verdict: str            # "FP" or "REAL"
    confidence: float       # 0.0 - 1.0
    weight: float           # how much this signal counts toward final decision
    reason: str
    evidence: Dict[str, Any]


# ── Built-in FP patterns ────────────────────────────────────────────────────

FP_PATTERNS = [
    # Benign scanner alerts
    {"pattern": r"\b(nessus|qualys|rapid7|openvas|nmap|nessuscli|nikto|burp|zap)\b.*\b(scan|probe|assessment)\b", "verdict": "FP",
     "confidence": 0.95, "reason": "Vulnerability scanner traffic"},
    {"pattern": r"\b(scan|probe)\b.*\b(completed|complete|finished)\b", "verdict": "FP",
     "confidence": 0.90, "reason": "Vulnerability scan completed"},
    {"pattern": r"\b(uptime|pingdom|datadog|prometheus|grafana|new\s*relic)\b.*\b(monitor|check|probe|alert)\b", "verdict": "FP",
     "confidence": 0.95, "reason": "Infrastructure monitoring traffic"},

    # Health checks
    {"pattern": r"\b(health[\s_-]?check|readiness[\s_-]?probe|liveness[\s_-]?probe|heartbeat)\b", "verdict": "FP",
     "confidence": 0.95, "reason": "Application health check"},
    {"pattern": r"GET\s+/health", "verdict": "FP", "confidence": 0.90,
     "reason": "HTTP health check request"},

    # Update / sync
    {"pattern": r"\b(yum|apt|dnf|brew|choco|apt-get)\s+(update|upgrade)", "verdict": "FP",
     "confidence": 0.90, "reason": "Package manager update"},
    {"pattern": r"signature.*update.*(complete|success)", "verdict": "FP",
     "confidence": 0.90, "reason": "Antivirus signature update completed"},

    # Backup / maintenance windows
    {"pattern": r"\b(backup|snapshot).*\b(started|completed|successful|finished)\b", "verdict": "FP",
     "confidence": 0.85, "reason": "Backup/snapshot operation"},

    # Test / staging
    {"pattern": r"\b(test|staging|dev|sandbox)([_-]?(env|host|server|box))?\b", "verdict": "FP",
     "confidence": 0.70, "reason": "Non-production environment"},
]


class FPDetector:
    """Signal 1: Rule-based false positive detection.

    Uses a curated list of regex patterns that almost always indicate benign activity.
    """

    def __init__(self):
        self.patterns = [(re.compile(p["pattern"], re.IGNORECASE), p) for p in FP_PATTERNS]
        self.weight = 0.30  # contribution to overall decision

    def check(self, alert) -> Signal:
        text = " ".join([
            str(getattr(alert, "title", "") or ""),
            str(getattr(alert, "description", "") or ""),
        ])
        for pattern, meta in self.patterns:
            if pattern.search(text):
                return Signal(
                    name="rule_based_fp",
                    verdict=meta["verdict"],
                    confidence=meta["confidence"],
                    weight=self.weight,
                    reason=meta["reason"],
                    evidence={"matched_pattern": meta["pattern"]},
                )
        # No pattern matched → not enough signal alone
        return Signal(
            name="rule_based_fp",
            verdict="REAL",
            confidence=0.5,
            weight=self.weight,
            reason="No benign pattern matched",
            evidence={},
        )


fp_detector = FPDetector()
