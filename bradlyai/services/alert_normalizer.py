"""BradlyAI Alert Normalizer — converts alerts from Splunk, Wazuh, Jira into a common shape.

The L1 Agent operates on NormalizedAlert regardless of source. Each source has its own
ingestion path, but after normalization, all alerts look the same.
"""
import hashlib
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

    Two alerts with the same signature are considered duplicates (same issue, different instances).
    """
    key = f"{alert.title}|{alert.asset}|{alert.source_ip}|{alert.user}|{alert.process}|{alert.mitre}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


# ── Source-specific parsers ──────────────────────────────────────────────────


def from_splunk(payload: dict) -> NormalizedAlert:
    """Normalize a Splunk alert (search result or notable event).

    Splunk typically sends:
    {
      "sid": "...",
      "search_name": "Suspicious PowerShell Activity",
      "result": {"src_ip": "...", "dest": "...", "user": "...", "host": "...", "command": "..."},
      "severity": "high" | "critical" | "medium" | "low",
      "time": "2026-06-22T10:00:00Z"
    }
    """
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
    """Normalize a Wazuh SIEM alert.

    Wazuh webhook typically sends:
    {
      "timestamp": "...",
      "rule": {"level": 12, "description": "...", "id": "...", "mitre": {"id": [...]}},
      "agent": {"name": "...", "ip": "..."},
      "data": {"srcip": "...", "action": "..."}
    }
    """
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
    """Normalize a Jira issue (security ticket).

    Jira webhook sends:
    {
      "key": "SEC-1234",
      "fields": {
        "summary": "Suspicious login",
        "description": "...",
        "priority": {"name": "High"},
        "labels": ["security", "siem"],
        "created": "2026-06-22T10:00:00.000+0000"
      }
    }
    """
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

import re

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
