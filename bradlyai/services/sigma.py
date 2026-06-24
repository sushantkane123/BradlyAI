"""Sigma rule engine — load, store, evaluate rules against log events.

Supports a subset of Sigma:
  - selection / filter (field=value, field|contains, field|startswith, field|endswith, field|re)
  - condition: 1 of selection_* | all of selection_* | selection_* and filter_*
  - logsource (product/category/service)
  - level, status, tags (incl. MITRE)

Evaluation is in-memory and approximate — we don't ship a full Sigma-to-SQL
backend (that would be sql-backend). Sufficient for first-pass alert triage.
"""
from __future__ import annotations

import datetime
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.models.sigma_rule import SigmaRuleModel

logger = logging.getLogger("bradlyai.sigma")


_SEVERITY_FROM_LEVEL = {
    "informational": "LOW", "low": "LOW",
    "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL",
}


def _eval_condition(field: str, op: str, value: Any, event: Dict[str, Any]) -> bool:
    """Evaluate one Sigma matcher against an event field."""
    actual = event.get(field)
    if actual is None:
        # Many SIEMs nest fields — try common alternates
        for prefix in ("event.", "winlog.", "log.", "details.", ""):
            actual = event.get(f"{prefix}{field}")
            if actual is not None:
                break
        if actual is None:
            return False
    actual_s = str(actual)
    value_s = str(value)
    if op == "" or op == "equals":
        return actual_s == value_s
    if op == "contains":
        return value_s.lower() in actual_s.lower()
    if op == "startswith":
        return actual_s.lower().startswith(value_s.lower())
    if op == "endswith":
        return actual_s.lower().endswith(value_s.lower())
    if op == "re":
        try:
            return bool(re.search(value_s, actual_s, re.IGNORECASE))
        except re.error:
            return False
    if op == "field":
        # field reference — resolved before reaching here
        return bool(actual)
    return False


def _eval_selection(selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """A selection block is a dict of field → (op, value). All must match."""
    for field, spec in selection.items():
        if isinstance(spec, dict):
            # Single nested matcher: {"field": "EventID", "contains": "4624"}
            inner_field = spec.get("field", field)
            for op, value in spec.items():
                if op == "field":
                    continue
                if not _eval_condition(inner_field, op, value, event):
                    return False
        else:
            if not _eval_condition(field, "", spec, event):
                return False
    return True


def _eval_condition_expression(expr: str, detections: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Evaluate a Sigma condition expression. Supports:
       - 'selection' (single)
       - 'selection and filter_*'
       - '1 of selection_*'
       - 'all of selection_*'
    """
    expr = expr.strip()
    # 'and' / 'or' / 'not' composition
    def _split(s: str) -> List[str]:
        out, buf, depth = [], "", 0
        for ch in s:
            if ch == "(":
                depth += 1
                buf += ch
            elif ch == ")":
                depth -= 1
                buf += ch
            elif ch == " " and depth == 0:
                if buf:
                    out.append(buf); buf = ""
            else:
                buf += ch
        if buf:
            out.append(buf)
        return out

    tokens = _split(expr)
    if "and" in tokens:
        parts = [t for t in tokens if t not in ("and", "or", "not")]
        if "and" in tokens and "or" not in tokens:
            return all(_eval_condition_expression(p, detections, event) for p in parts)
        if "or" in tokens:
            return any(_eval_condition_expression(p, detections, event) for p in parts)
    if expr.startswith("1 of "):
        prefix = expr[len("1 of "):].strip().rstrip("*")
        return any(_eval_selection(detections[k], event)
                   for k in detections if k.startswith(prefix))
    if expr.startswith("all of "):
        prefix = expr[len("all of "):].strip().rstrip("*")
        return all(_eval_selection(detections[k], event)
                   for k in detections if k.startswith(prefix))
    if expr in detections:
        return _eval_selection(detections[expr], event)
    return False


def evaluate_rule(rule: SigmaRuleModel, event: Dict[str, Any]) -> bool:
    """Return True if the rule's detection block matches the event."""
    detection = rule.detection_json or {}
    if not detection:
        return False
    # logsource filter
    ls = detection.get("logsource", {})
    if ls:
        if ls.get("product") and ls["product"] != event.get("logsource_product"):
            return False
        if ls.get("category") and ls["category"] != event.get("logsource_category"):
            return False
    # Strip logsource before evaluating conditions
    cond_expr = detection.get("condition", "selection")
    detections = {k: v for k, v in detection.items() if k not in ("logsource", "condition", "timeframe", "fields")}
    try:
        return _eval_condition_expression(cond_expr, detections, event)
    except Exception as exc:
        logger.debug(f"Sigma eval failed for rule {rule.id}: {exc}")
        return False


def load_yaml_rule(text: str) -> Optional[SigmaRuleModel]:
    """Parse a Sigma YAML rule and return a SigmaRuleModel (not yet committed)."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.error(f"Sigma YAML parse error: {exc}")
        return None
    if not isinstance(data, dict):
        return None
    detection = data.get("detection") or {}
    return SigmaRuleModel(
        id=data.get("id") or f"sigma_{datetime.datetime.now().timestamp():.0f}",
        title=data.get("title", "Untitled"),
        description=data.get("description"),
        level=data.get("level", "medium"),
        status=data.get("status", "experimental"),
        logsource_product=(data.get("logsource") or {}).get("product"),
        logsource_category=(data.get("logsource") or {}).get("category"),
        logsource_service=(data.get("logsource") or {}).get("service"),
        detection_json=detection,
        fields_json=data.get("fields"),
        falsepositives_json=data.get("falsepositives"),
        references_json=data.get("references"),
        tags_json=data.get("tags"),
        author=data.get("author"),
        date=_parse_date(data.get("date")),
        modified=_parse_date(data.get("modified")),
        raw_yaml=text,
        enabled=True,
        tenant_id=settings.DEFAULT_TENANT_ID,
    )


def _parse_date(value: Any) -> Optional[datetime.datetime]:
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        return value
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.datetime.min.time())
    try:
        return datetime.datetime.fromisoformat(str(value))
    except Exception:
        return None


def import_rule_file(db: Session, path: str) -> Optional[SigmaRuleModel]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    rule = load_yaml_rule(text)
    if rule is None:
        return None
    existing = db.query(SigmaRuleModel).filter(SigmaRuleModel.id == rule.id).first()
    if existing:
        for attr in ("title", "description", "level", "status", "logsource_product",
                     "logsource_category", "logsource_service", "detection_json",
                     "fields_json", "falsepositives_json", "references_json",
                     "tags_json", "author", "date", "modified", "raw_yaml"):
            setattr(existing, attr, getattr(rule, attr))
        db.commit()
        return existing
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def import_rule_directory(db: Session, directory: str) -> Tuple[int, int]:
    """Walk a directory and import all *.yml/*.yaml files as Sigma rules."""
    imported, failed = 0, 0
    root = Path(directory)
    if not root.exists():
        return 0, 0
    for path in root.rglob("*.y*ml"):
        try:
            if import_rule_file(db, str(path)) is not None:
                imported += 1
            else:
                failed += 1
        except Exception as exc:
            logger.error(f"Failed to import {path}: {exc}")
            failed += 1
    return imported, failed


def seed_default_sigma_rules(db: Session) -> int:
    """Seed a small built-in Sigma rule library on first boot."""
    defaults = [
        {
            "id": "bradlyai_sigma_powershell_encoded",
            "title": "Suspicious Encoded PowerShell Execution",
            "level": "high",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "logsource": {"product": "windows", "category": "process_creation"},
                "selection": {
                    "Image": {"endswith": "\\powershell.exe"},
                    "CommandLine": {"contains": "-EncodedCommand"},
                },
                "condition": "selection",
            },
            "tags": ["attack.execution", "attack.t1059.001"],
        },
        {
            "id": "bradlyai_sigma_mimikatz",
            "title": "Potential Mimikatz Execution",
            "level": "critical",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "logsource": {"product": "windows", "category": "process_creation"},
                "selection": {"Image": {"contains": "mimikatz"}},
                "condition": "selection",
            },
            "tags": ["attack.credential_access", "attack.t1003"],
        },
        {
            "id": "bradlyai_sigma_suspicious_dns",
            "title": "DNS Query to Suspicious TLD",
            "level": "medium",
            "logsource": {"product": "zeek", "category": "dns"},
            "detection": {
                "logsource": {"product": "zeek", "category": "dns"},
                "selection_query": {"query": {"re": r".*\.(tk|ml|ga|cf)$"}},
                "condition": "selection_query",
            },
            "tags": ["attack.command_and_control", "attack.t1071.004"],
        },
    ]
    count = 0
    for spec in defaults:
        rule = SigmaRuleModel(
            id=spec["id"], title=spec["title"], level=spec["level"],
            status="stable",
            logsource_product=spec["logsource"]["product"],
            logsource_category=spec["logsource"]["category"],
            detection_json=spec["detection"],
            tags_json=spec.get("tags"),
            enabled=True,
            tenant_id=settings.DEFAULT_TENANT_ID,
        )
        existing = db.query(SigmaRuleModel).filter(SigmaRuleModel.id == rule.id).first()
        if existing:
            continue
        db.add(rule)
        count += 1
    db.commit()
    return count


def evaluate_event(db: Session, event: Dict[str, Any], tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Run all enabled rules against an event. Return matching alert summaries."""
    q = db.query(SigmaRuleModel).filter(SigmaRuleModel.enabled == True)
    if tenant_id:
        q = q.filter((SigmaRuleModel.tenant_id == tenant_id) | (SigmaRuleModel.tenant_id == None))  # noqa: E711
    matches = []
    for rule in q.all():
        try:
            if evaluate_rule(rule, event):
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "level": rule.level,
                    "severity": _SEVERITY_FROM_LEVEL.get(rule.level, "MEDIUM"),
                    "tags": rule.tags_json or [],
                })
        except Exception:
            continue
    return matches
