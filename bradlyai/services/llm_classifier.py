"""BradlyAI LLM Classifier — uses Groq/OpenAI to semantically classify alerts as FP or REAL."""
import json
import logging
import re
from typing import Optional
from bradlyai.services.fp_detector import Signal
from bradlyai.services.llm_client import llm_client

logger = logging.getLogger("bradlyai.llm_classifier")


SYSTEM_PROMPT = """You are an L1 SOC analyst with 15 years of experience triaging alerts.
Your job: classify alerts as FALSE POSITIVE (FP) or REAL THREAT.

A FALSE POSITIVE is any alert that does NOT represent actual harm — including:
- Internal vulnerability scans, monitoring probes, health checks
- Known-benign software (updates, backup agents, AV signatures)
- Duplicate alerts (same alert firing repeatedly with no action taken)
- Test environments, synthetic transactions
- Misconfigured thresholds catching normal activity

A REAL THREAT represents actual harm — including:
- Unauthorized access, privilege escalation, lateral movement
- Malware execution, C2 communication, data exfiltration
- Credential theft, persistence mechanisms
- Active exploitation of vulnerabilities

Respond with a JSON object only, no markdown, no preamble:
{"verdict": "FP" or "REAL", "confidence": 0.0-1.0, "reason": "one sentence explanation"}"""


class LLMClassifier:
    """Signal 4: LLM-based semantic classification.

    Disabled if no API key configured. Falls back to neutral signal.
    """

    def __init__(self):
        self.weight = 0.30

    def is_available(self) -> bool:
        # Treat empty / placeholder keys as unavailable
        key = (llm_client.api_key or "").strip()
        if not key:
            return False
        placeholders = ("your_key_here", "replace_me", "changeme", "xxx", "todo")
        return not any(p in key.lower() for p in placeholders)

    async def check(self, alert) -> Signal:
        if not self.is_available():
            return Signal(
                name="llm_classifier",
                verdict="REAL",
                confidence=0.5,
                weight=self.weight,
                reason="LLM not configured (no API key)",
                evidence={"available": False},
            )

        user_prompt = f"""Classify this security alert:

Title: {getattr(alert, "title", "")}
Description: {getattr(alert, "description", "")}
Severity: {getattr(alert, "severity", "UNKNOWN")}
Source: {getattr(alert, "source", "unknown")}
Asset: {getattr(alert, "asset", "unknown")}
Source IP: {getattr(alert, "source_ip", "unknown")}
User: {getattr(alert, "user", "unknown")}
MITRE: {getattr(alert, "mitre", "none")}

Respond with JSON only."""

        try:
            raw = await llm_client.generate_response(user_prompt, SYSTEM_PROMPT)
            parsed = self._parse_json(raw)
            if parsed:
                return Signal(
                    name="llm_classifier",
                    verdict=parsed.get("verdict", "REAL").upper(),
                    confidence=float(parsed.get("confidence", 0.5)),
                    weight=self.weight,
                    reason=parsed.get("reason", "LLM verdict"),
                    evidence={"llm_response": parsed},
                )
        except Exception as e:
            logger.warning(f"LLM classification failed: {e}")

        return Signal(
            name="llm_classifier",
            verdict="REAL",
            confidence=0.5,
            weight=self.weight,
            reason="LLM classification failed or unparseable",
            evidence={"error": True},
        )

    def _parse_json(self, text: str) -> Optional[dict]:
        """Extract JSON from LLM response (it sometimes wraps in markdown)."""
        # Try direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try extracting from ```json blocks
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                pass
        # Try finding first { ... } block
        m = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
        return None


llm_classifier = LLMClassifier()
