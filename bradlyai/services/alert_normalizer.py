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


def _as_severity(value: Any, default: str = "MEDIUM") -> str:
    """Map common SIEM/XDR severities and numeric scores to the shared four-level scale."""
    text = str(value or "").strip().upper()
    aliases = {
        "INFORMATIONAL": "LOW", "INFO": "LOW", "NOTICE": "LOW", "LOW": "LOW",
        "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "MED": "MEDIUM",
        "HIGH": "HIGH", "SEVERE": "HIGH", "MAJOR": "HIGH",
        "CRITICAL": "CRITICAL", "FATAL": "CRITICAL", "VERY_HIGH": "CRITICAL",
    }
    if text in aliases:
        return aliases[text]
    try:
        score = float(text)
        if score >= 90: return "CRITICAL"
        if score >= 70: return "HIGH"
        if score >= 40: return "MEDIUM"
        return "LOW"
    except ValueError:
        return default


def _first_non_empty(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "", [], {})), None)


def _entity_value(entities: Any, *keys: str) -> Optional[str]:
    """Extract a useful entity value from Sentinel/Defender-style entity lists."""
    if not isinstance(entities, list):
        return None
    requested = {key.lower() for key in keys}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("Type") or entity.get("type") or "").lower()
        if entity_type and entity_type not in requested:
            continue
        value = _first_non_empty(entity.get("HostName"), entity.get("Name"), entity.get("Address"), entity.get("AccountName"), entity.get("id"))
        if value:
            return str(value)
    return None


def _build_alert(source: str, payload: dict, *, prefix: str, identifier: Any, title: Any,
                 description: Any = "", severity: Any = "MEDIUM", asset: Any = None,
                 source_ip: Any = None, user: Any = None, process: Any = None,
                 domain: Any = None, mitre: Any = None, timestamp: Any = None) -> NormalizedAlert:
    safe_id = str(identifier or hashlib.md5(str(payload).encode()).hexdigest()[:10])
    alert = NormalizedAlert(
        id=f"{prefix}-{safe_id}", source=source,
        title=str(title or f"{source.title()} alert"), description=str(description or title or ""),
        severity=_as_severity(severity), asset=str(asset) if asset else None,
        source_ip=str(source_ip) if source_ip else None, user=str(user) if user else None,
        process=str(process) if process else None, domain=str(domain) if domain else None,
        mitre=str(mitre) if mitre else None,
        timestamp=str(timestamp or datetime.now(timezone.utc).isoformat()), raw=payload,
    )
    alert.signature = make_signature(alert)
    return alert


def from_sentinel(payload: dict) -> NormalizedAlert:
    """Normalize Microsoft Sentinel Common Alert Schema or incident-style alerts."""
    entities = payload.get("Entities") or payload.get("entities") or []
    extended = payload.get("ExtendedProperties") or payload.get("extendedProperties") or {}
    return _build_alert(
        "sentinel", payload, prefix="SEN",
        identifier=_first_non_empty(payload.get("SystemAlertId"), payload.get("AlertId"), payload.get("id")),
        title=_first_non_empty(payload.get("AlertDisplayName"), payload.get("DisplayName"), payload.get("title")),
        description=_first_non_empty(payload.get("Description"), payload.get("description")),
        severity=_first_non_empty(payload.get("Severity"), payload.get("AlertSeverity"), payload.get("severity")),
        asset=_first_non_empty(payload.get("CompromisedEntity"), _entity_value(entities, "host", "machine")),
        source_ip=_first_non_empty(_entity_value(entities, "ip", "ipaddress"), extended.get("SourceIP")),
        user=_entity_value(entities, "account", "user"),
        process=_first_non_empty(extended.get("Process"), extended.get("CommandLine")),
        mitre=_first_non_empty(payload.get("Tactics"), payload.get("Techniques"), extended.get("MITRETechniques")),
        timestamp=_first_non_empty(payload.get("StartTimeUtc"), payload.get("TimeGenerated"), payload.get("timestamp")),
    )


def from_defender(payload: dict) -> NormalizedAlert:
    """Normalize Microsoft Defender for Endpoint alert payloads."""
    entities = payload.get("entities") or payload.get("Entities") or []
    return _build_alert(
        "defender", payload, prefix="MDE",
        identifier=_first_non_empty(payload.get("id"), payload.get("alertId"), payload.get("alert_id")),
        title=_first_non_empty(payload.get("alertTitle"), payload.get("title"), payload.get("name")),
        description=_first_non_empty(payload.get("description"), payload.get("alertDescription")),
        severity=_first_non_empty(payload.get("severity"), payload.get("alertSeverity")),
        asset=_first_non_empty(payload.get("deviceName"), payload.get("machineName"), _entity_value(entities, "host", "device", "machine")),
        source_ip=_first_non_empty(payload.get("sourceIp"), payload.get("ipAddress"), _entity_value(entities, "ip", "ipaddress")),
        user=_first_non_empty(payload.get("userName"), _entity_value(entities, "user", "account")),
        process=_first_non_empty(payload.get("processName"), payload.get("processCommandLine")),
        mitre=_first_non_empty(payload.get("mitreTechniques"), payload.get("mitre")),
        timestamp=_first_non_empty(payload.get("createdDateTime"), payload.get("alertCreationTime"), payload.get("timestamp")),
    )


def from_crowdstrike(payload: dict) -> NormalizedAlert:
    """Normalize CrowdStrike Falcon detection event or API resource payloads."""
    resource = payload.get("resources", [payload])
    event = resource[0] if isinstance(resource, list) and resource else payload
    behaviors = event.get("behaviors") or []
    behavior = behaviors[0] if isinstance(behaviors, list) and behaviors else {}
    device = event.get("device") or {}
    return _build_alert(
        "crowdstrike", payload, prefix="CS",
        identifier=_first_non_empty(event.get("detection_id"), event.get("id"), payload.get("id")),
        title=_first_non_empty(behavior.get("description"), behavior.get("tactic"), event.get("name"), event.get("status")),
        description=_first_non_empty(behavior.get("description"), event.get("description"), behavior.get("cmdline")),
        severity=_first_non_empty(behavior.get("severity"), event.get("max_severity_displayname"), event.get("severity")),
        asset=_first_non_empty(device.get("hostname"), event.get("device_hostname")),
        source_ip=_first_non_empty(device.get("local_ip"), device.get("external_ip"), event.get("local_ip")),
        user=_first_non_empty(behavior.get("user_name"), event.get("user_name")),
        process=_first_non_empty(behavior.get("filename"), behavior.get("cmdline")),
        mitre=_first_non_empty(behavior.get("technique"), behavior.get("tactic")),
        timestamp=_first_non_empty(event.get("first_behavior"), event.get("created_timestamp"), payload.get("timestamp")),
    )


def from_elastic(payload: dict) -> NormalizedAlert:
    """Normalize Elastic Security detection payloads, including Elasticsearch _source envelopes."""
    event = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
    rule = event.get("kibana.alert.rule") or event.get("rule") or {}
    host = event.get("host") or {}
    process = event.get("process") or {}
    user = event.get("user") or {}
    source = event.get("source") or {}
    threat = event.get("threat") or {}
    technique = threat.get("technique") or {}
    return _build_alert(
        "elastic", payload, prefix="ELK",
        identifier=_first_non_empty(payload.get("_id"), event.get("event.id"), event.get("id")),
        title=_first_non_empty(rule.get("name"), event.get("message"), event.get("event.action")),
        description=_first_non_empty(rule.get("description"), event.get("message")),
        severity=_first_non_empty(event.get("kibana.alert.severity"), rule.get("severity"), event.get("severity")),
        asset=_first_non_empty(host.get("name"), host.get("hostname")),
        source_ip=_first_non_empty(source.get("ip"), event.get("source.ip")),
        user=_first_non_empty(user.get("name"), event.get("user.name")),
        process=_first_non_empty(process.get("name"), process.get("executable")),
        mitre=_first_non_empty(technique.get("id"), event.get("threat.technique.id")),
        timestamp=_first_non_empty(event.get("@timestamp"), event.get("timestamp")),
    )


def from_generic(source: str, payload: dict) -> NormalizedAlert:
    """Normalize common alert fields from any SIEM, XDR, EDR, SOAR, or custom webhook."""
    return _build_alert(
        source, payload, prefix="EVT",
        identifier=_first_non_empty(payload.get("id"), payload.get("event_id"), payload.get("alert_id")),
        title=_first_non_empty(payload.get("title"), payload.get("name"), payload.get("message"), payload.get("description")),
        description=_first_non_empty(payload.get("description"), payload.get("message"), payload.get("title")),
        severity=_first_non_empty(payload.get("severity"), payload.get("priority"), payload.get("risk_score")),
        asset=_first_non_empty(payload.get("asset"), payload.get("host"), payload.get("endpoint"), payload.get("device")),
        source_ip=_first_non_empty(payload.get("source_ip"), payload.get("src_ip"), payload.get("ip")),
        user=_first_non_empty(payload.get("user"), payload.get("username")),
        process=_first_non_empty(payload.get("process"), payload.get("process_name")),
        domain=_first_non_empty(payload.get("domain"), payload.get("url")),
        mitre=_first_non_empty(payload.get("mitre"), payload.get("mitre_technique")),
        timestamp=_first_non_empty(payload.get("timestamp"), payload.get("time"), payload.get("created_at")),
    )


def normalize(source: str, payload: dict) -> NormalizedAlert:
    """Top-level normalizer for SIEM, XDR, EDR, SOAR, and generic webhook events."""
    source_key = source.lower().strip().replace("-", "_")
    parsers = {
        "splunk": from_splunk,
        "wazuh": from_wazuh,
        "jira": from_jira,
        "bradlyai": from_bradlyai,
        "sentinel": from_sentinel,
        "microsoft_sentinel": from_sentinel,
        "defender": from_defender,
        "microsoft_defender": from_defender,
        "mde": from_defender,
        "crowdstrike": from_crowdstrike,
        "falcon": from_crowdstrike,
        "elastic": from_elastic,
        "elasticsearch": from_elastic,
        "elk": from_elastic,
        "siem": lambda event: from_generic("siem", event),
        "xdr": lambda event: from_generic("xdr", event),
        "edr": lambda event: from_generic("edr", event),
        "generic": lambda event: from_generic("generic", event),
    }
    parser = parsers.get(source_key)
    if not parser:
        raise ValueError(f"Unknown alert source: {source}. Supported: {', '.join(sorted(parsers))}")
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
