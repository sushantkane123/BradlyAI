"""Evidence-first SOC investigation agent.

This is deliberately not an unconstrained chatbot. It follows a repeatable L1/L2
workflow: validate an alert, formulate hypotheses, collect available evidence,
identify missing evidence, correlate local history, and recommend a *policy-gated*
disposition. It never performs containment itself.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from bradlyai.models.alert import AlertModel
from bradlyai.models.investigation import InvestigationModel

SUSPICIOUS_TERMS = {
    "malware", "ransomware", "credential", "credential dumping", "mimikatz",
    "powershell", "encoded", "brute force", "lateral movement", "exfiltration",
    "persistence", "exploit", "suspicious process", "privilege escalation",
}
BENIGN_TERMS = {
    "scanner", "nessus", "healthcheck", "heartbeat", "inventory", "backup",
    "monitoring", "vulnerability scan", "patch management",
}


@dataclass(frozen=True)
class InvestigationResult:
    plan: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    recommendation: str
    confidence: float
    summary: str
    policy: dict[str, Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _raw(alert: AlertModel) -> dict[str, Any]:
    if not alert.raw_event:
        return {}
    try:
        data = json.loads(alert.raw_event)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _contains_term(text: str, terms: set[str]) -> list[str]:
    lower = text.lower()
    return sorted(term for term in terms if term in lower)


def _severity_rank(severity: str | None) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(severity or "").upper(), 2)


def _evidence(kind: str, source: str, title: str, finding: str, confidence: str = "observed") -> dict[str, Any]:
    return {
        "type": kind,
        "source": source,
        "title": title,
        "finding": finding,
        "confidence": confidence,
        "collected_at": _now().isoformat(),
    }


def build_investigation(db: Session, alert: AlertModel) -> InvestigationResult:
    """Build a human-reviewable investigation from stored source evidence and history."""
    raw = _raw(alert)
    corpus = " ".join(str(value) for value in (alert.title, alert.raw_event, alert.mitre, alert.source)).lower()
    suspicious_hits = _contains_term(corpus, SUSPICIOUS_TERMS)
    benign_hits = _contains_term(corpus, BENIGN_TERMS)
    cutoff = _now() - timedelta(hours=24)

    same_signature = db.query(AlertModel).filter(
        AlertModel.signature == alert.signature,
        AlertModel.id != alert.id,
        AlertModel.created_at >= cutoff,
    ).all() if alert.signature else []
    same_asset = db.query(AlertModel).filter(
        AlertModel.endpoint == alert.endpoint,
        AlertModel.id != alert.id,
        AlertModel.created_at >= cutoff,
    ).count() if alert.endpoint and alert.endpoint != "unknown" else 0

    plan = [
        {"step": 1, "task": "Validate source event and normalize entities", "status": "completed", "reason": f"Event received from {alert.source or 'unknown source'}."},
        {"step": 2, "task": "Correlate recent matching alerts", "status": "completed", "reason": f"Found {len(same_signature)} matching signature event(s) in the previous 24 hours."},
        {"step": 3, "task": "Review endpoint context", "status": "completed" if alert.endpoint and alert.endpoint != "unknown" else "missing_evidence", "reason": alert.endpoint or "No endpoint/host was supplied by the source."},
        {"step": 4, "task": "Review identity and network context", "status": "pending_connector", "reason": "Requires approved identity, EDR, DNS, proxy, or firewall connector queries."},
        {"step": 5, "task": "Assess policy and recommend disposition", "status": "completed", "reason": "Recommendation is constrained by severity and observed evidence."},
    ]

    evidence = [
        _evidence("source_event", alert.source or "unknown", "Original source event retained", f"Alert {alert.id} was normalized from a retained source payload."),
        _evidence("asset", alert.source or "unknown", "Endpoint context", f"Asset: {alert.endpoint or 'not provided'}; source IP: {alert.ip or 'not provided'}."),
        _evidence("correlation", "BradlyAI", "Recent signature correlation", f"{len(same_signature)} matching signature event(s) and {same_asset} event(s) on the same asset in 24 hours."),
    ]
    if alert.mitre:
        evidence.append(_evidence("mitre", alert.source or "unknown", "MITRE mapping", str(alert.mitre)))
    if suspicious_hits:
        evidence.append(_evidence("risk_signal", "BradlyAI", "High-risk behavior terms", ", ".join(suspicious_hits), "inferred_from_source_event"))
    if benign_hits:
        evidence.append(_evidence("benign_signal", "BradlyAI", "Known operational terms", ", ".join(benign_hits), "inferred_from_source_event"))
    if raw:
        evidence.append(_evidence("provenance", alert.source or "unknown", "Raw event availability", "Original JSON event is preserved with the normalized alert."))

    severity = _severity_rank(alert.severity)
    hypotheses: list[dict[str, Any]] = []
    if suspicious_hits or severity >= 3:
        hypotheses.append({
            "hypothesis": "Potential malicious or policy-violating activity",
            "confidence": min(0.95, 0.45 + severity * 0.11 + 0.06 * len(suspicious_hits)),
            "supporting_evidence": ["severity", "risk_signal", "mitre"],
            "next_action": "Query endpoint, identity, and network telemetry before containment.",
        })
    if benign_hits:
        hypotheses.append({
            "hypothesis": "Expected operational or scanner activity",
            "confidence": min(0.85, 0.35 + 0.10 * len(benign_hits) + 0.04 * len(same_signature)),
            "supporting_evidence": ["benign_signal", "correlation"],
            "next_action": "Validate against an approved scanner/service-account policy or analyst-approved resolution memory.",
        })
    if not hypotheses:
        hypotheses.append({
            "hypothesis": "Insufficient contextual evidence to classify the event",
            "confidence": 0.50,
            "supporting_evidence": ["source_event"],
            "next_action": "Collect identity, endpoint, and network context through approved connectors.",
        })

    # Safety policy: a high/critical alert is never an auto-close candidate based
    # solely on local matching or an LLM-style inference.
    policy = {
        "rule": "high_or_critical_never_auto_close_without_human_approval",
        "severity": str(alert.severity or "MEDIUM").upper(),
        "matching_signature_events_24h": len(same_signature),
        "requires_external_connector_evidence": True,
    }
    if severity >= 3 or suspicious_hits:
        recommendation = "ESCALATE"
        confidence = max(hypothesis["confidence"] for hypothesis in hypotheses)
        summary = "Escalate for analyst review. Severity or observed behavior indicates that connector-backed endpoint, identity, and network evidence is required."
    elif benign_hits and len(same_signature) >= 1:
        recommendation = "AUTO_CLOSE_CANDIDATE"
        confidence = max(hypothesis["confidence"] for hypothesis in hypotheses)
        summary = "Potentially benign recurring activity. Do not close automatically until an analyst-approved resolution memory and tenant policy both match."
    else:
        recommendation = "REVIEW"
        confidence = max(hypothesis["confidence"] for hypothesis in hypotheses)
        summary = "Keep open for analyst review. Current evidence does not justify an automatic disposition."

    return InvestigationResult(
        plan=plan,
        evidence=evidence,
        hypotheses=hypotheses,
        recommendation=recommendation,
        confidence=round(confidence, 3),
        summary=summary,
        policy=policy,
    )


def run_investigation(db: Session, alert: AlertModel) -> InvestigationModel:
    result = build_investigation(db, alert)
    investigation = InvestigationModel(
        alert_id=alert.id,
        tenant_id=alert.tenant_id,
        status="COMPLETED",
        recommendation=result.recommendation,
        confidence=f"{result.confidence:.0%}",
        summary=result.summary,
        plan_json=result.plan,
        evidence_json=result.evidence,
        hypotheses_json=result.hypotheses,
        policy_json=result.policy,
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


def to_dict(investigation: InvestigationModel) -> dict[str, Any]:
    return {
        "id": investigation.id,
        "alert_id": investigation.alert_id,
        "tenant_id": investigation.tenant_id,
        "status": investigation.status,
        "recommendation": investigation.recommendation,
        "confidence": investigation.confidence,
        "summary": investigation.summary,
        "plan": investigation.plan_json or [],
        "evidence": investigation.evidence_json or [],
        "hypotheses": investigation.hypotheses_json or [],
        "policy": investigation.policy_json or {},
        "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
        "updated_at": investigation.updated_at.isoformat() if investigation.updated_at else None,
    }
