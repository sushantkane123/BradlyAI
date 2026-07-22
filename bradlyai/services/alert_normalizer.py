"""Optimized BradlyAI Alert Normalizer — collision-safe signature generation.

Gains:
- Collision Prevention: Ensures that alerts with empty or default values (e.g. None) on critical 
  attributes do not share the exact same hash signature, preventing false-positive de-duplication closures.
- Signature Reliability: Adds unique salt markers (like alert ID or timestamp windows) if 
  insufficient identifying information is present.
- Full Parser Preservation: Retains all source-specific parser functions (Splunk, Wazuh, Jira, BradlyAI)
  and the primary normalize route intact.
"""

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from dataclasses import dataclass, field, asdict

@dataclass
class NormalizedAlert:
    """Common shape every L1 Agent decision operates on."""
    id: str
    source: str                     # splunk / wazuh / jira / bradlyai
    title: str
    description: str
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW
    asset: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    domain: Optional[str] = None
    mitre: Optional[str] = None
    timestamp: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""             # hash for duplicate detection

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


# ── Source-specific parsers ──────────────────────────────────────────────────


def from_splunk(payload: dict) -> NormalizedAlert:
    """Normalize a Splunk alert (search result or notable event)."""
    result = payload.get("result", {}) or {}
    sev = (payload.get("severity") or "medium").upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sev = "MEDIUM"
    alert = NormalizedAlert(
        id=f"SPL-{payload.get('sid', hashlib.md5(str(payload).encode()).hexdigest()[:10])}",
        source="splunk",
        title=payload.get("search_name", "Splunk Alert"),
        description=result.get("command") or payload.get("description", ""),
        severity=sev,
        asset=result.get("host") or result.get("dest"),
        source_ip=result.get("src_ip") or result.get("src"),
        user=result.get("user"),
        process=result.get("process_name") or result.get("command", "").split()[0] if result.get("command") else None,
        domain=result.get("url_domain"),
        mitre=result.get("mitre_attack"),
        timestamp=payload.get("time") or datetime.now(timezone.utc).isoformat(),
        raw=payload,
    )
    alert.signature = make_signature(alert)
    return alert


def from_wazuh(payload: dict) -> NormalizedAlert:
    """Normalize a Wazuh SIEM alert."""
    rule = payload.get("rule", {}) or {}
    agent = payload.get("agent", {}) or {}
    data = payload.get("data", {}) or {}
    level = rule.get("level", 0)
    if level >= 12:
        sev = "CRITICAL"
    elif level >= 8:
        sev = "HIGH"
    elif level >= 4:
        sev = "MEDIUM"
    else:
        sev = "LOW"
    mitre_ids = (rule.get("mitre", {}) or {}).get("id", [])
    mitre = ", ".join(mitre_ids) if mitre_ids else None
    alert = NormalizedAlert(
        id=f"WAZ-{payload.get('id', hashlib.md5(str(payload).encode()).hexdigest()[:10])}",
        source="wazuh",
        title=rule.get("description", "Wazuh Alert"),
        description=rule.get("description", ""),
        severity=sev,
        asset=agent.get("name"),
        source_ip=agent.get("ip") or data.get("srcip"),
        user=data.get("user") or data.get("username"),
        process=data.get("process"),
        domain=data.get("url"),
        mitre=mitre,
        timestamp=payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        raw=payload,
    )
    alert.signature = make_signature(alert)
    return alert


def from_jira(payload: dict) -> NormalizedAlert:
    """Normalize a Jira issue (security ticket)."""
    fields = payload.get("fields", {}) or {}
    priority = (fields.get("priority") or {}).get("name", "Medium").upper()
    sev_map = {"HIGHEST": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "LOWEST": "LOW"}
    sev = sev_map.get(priority, "MEDIUM")
    description = fields.get("description", "") or ""
    alert = NormalizedAlert(
        id=f"JIRA-{payload.get('key', '')}",
        source="jira",
        title=fields.get("summary", "Jira Issue"),
        description=description[:500],
        severity=sev,
        asset=_extract_asset_from_text(description),
        source_ip=_extract_ip_from_text(description),
        user=(fields.get("reporter") or {}).get("displayName"),
        mitre=None,
        timestamp=fields.get("created"),
        raw=payload,
    )
    alert.signature = make_signature(alert)
    return alert


def from_bradlyai(payload: dict) -> NormalizedAlert:
    """Normalize an alert produced by BradlyAI's own detection engine."""
    alert = NormalizedAlert(
        id=f"B-{payload.get('id', hashlib.md5(str(payload).encode()).hexdigest()[:10])}",
        source="bradlyai",
        title=payload.get("title", "BradlyAI Alert"),
        description=payload.get("description", payload.get("title", "")),
        severity=(payload.get("severity") or "MEDIUM").upper(),
        asset=payload.get("endpoint"),
        source_ip=payload.get("ip"),
        user=payload.get("user"),
        process=payload.get("process"),
        mitre=payload.get("mitre"),
        timestamp=payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        raw=payload,
    )
    alert.signature = make_signature(alert)
    return alert


def normalize(source: str, payload: dict) -> NormalizedAlert:
    """Top-level normalizer — dispatches to the right parser."""
    parsers = {
        "splunk": from_splunk,
        "wazuh": from_wazuh,
        "jira": from_jira,
        "bradlyai": from_bradlyai,
    }
    parser = parsers.get(source.lower())
    if not parser:
        raise ValueError(f"Unknown alert source: {source}. Supported: {list(parsers.keys())}")
    return parser(payload)


# ── Helpers ──────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|local|internal)\b")


def _extract_ip_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    m = _IP_RE.search(text)
    return m.group(0) if m else None


def _extract_asset_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    m = _HOST_RE.search(text)
    return m.group(0) if m else None
