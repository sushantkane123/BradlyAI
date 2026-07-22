"""Optimized BradlyAI Alert Normalizer — collision-safe signature generation.

Gains:
- Collision Prevention: Ensures that alerts with empty or default values (e.g. None) on critical 
  attributes do not share the exact same hash signature, preventing false-positive de-duplication closures.
- Signature Reliability: Adds unique salt markers (like alert ID or timestamp windows) if 
  insufficient identifying information is present.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass, field, asdict

@dataclass
class NormalizedAlert:
    id: str
    source: str  # splunk / wazuh / jira / bradlyai
    title: str
    description: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    asset: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    domain: Optional[str] = None
    mitre: Optional[str] = None
    timestamp: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""  # hash for duplicate detection

    def to_dict(self) -> dict:
        return asdict(self)

def make_signature(alert: NormalizedAlert) -> str:
    """Generate a stable signature for duplicate detection.
    
    Collision Guard: If an alert is missing vital identifying characteristics 
    (e.g., has no source IP, asset hostname, or process information), 
    we introduce the alert ID to ensure it is evaluated independently. 
    Otherwise, generic alerts would generate identical hashes (e.g. 'Brute Force|None|None|None')
    and cause separate hosts to be mistakenly auto-closed as duplicates.
    """
    # Define vital identifying metrics
    has_identity = any([alert.asset, alert.source_ip, alert.user, alert.process])

    if not has_identity:
        # Secure fallback: Treat this alert as unique to prevent duplicate masking
        unique_marker = f"{alert.id}|{alert.title}|{alert.source}"
        return hashlib.sha256(unique_marker.encode()).hexdigest()[:32]

    # Clean None values dynamically to prevent string representation 'None' collisions
    asset = alert.asset or ""
    source_ip = alert.source_ip or ""
    user = alert.user or ""
    process = alert.process or ""
    mitre = alert.mitre or ""

    key = f"{alert.title}|{asset}|{source_ip}|{user}|{process}|{mitre}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]
