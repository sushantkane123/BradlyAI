"""BradlyAI Input/Output Safety Guardrails — Prompt Injection & Abuse Interceptor.

Gains:
- Prompt Injection Prevention: Inspects user-provided external log and alert telemetry
  before sending them to cloud or local LLM reasoning loops.
- Compliance Aligned: Standard sanitization vectors.
"""

import re
import logging

logger = logging.getLogger("bradlyai.guardrails")

class SafetyGuardrails:
    def __init__(self):
        # High-precision patterns of prompt injection & command override signatures
        self.injection_patterns = [
            re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
            re.compile(r"system\s+override", re.IGNORECASE),
            re.compile(r"you\s+must\s+ignore\s+the\s+alert", re.IGNORECASE),
            re.compile(r"output\s+the\s+following\s+json\s+block", re.IGNORECASE),
            re.compile(r"classify\s+this\s+as\s+fp", re.IGNORECASE),
            re.compile(r"do\s+not\s+report\s+any\s+alerts", re.IGNORECASE),
            re.compile(r"override\s+system\s+directives", re.IGNORECASE),
        ]

    def is_safe(self, text: str) -> bool:
        """Scan untrusted inputs for prompt injection vectors.
        
        Returns False if any malicious override or formatting escape pattern matches.
        """
        if not text:
            return True
        for pattern in self.injection_patterns:
            if pattern.search(text):
                logger.warning(f"Adversarial alert prompt injection pattern blocked: {pattern.pattern}")
                return False
        return True

guardrails = SafetyGuardrails()
