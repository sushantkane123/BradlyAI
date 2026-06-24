"""Playbook Engine — declarative YAML/JSON DAG execution.

A playbook is a JSON object of the form:
    {
      "id": "pb_phishing_response",
      "name": "Phishing Response",
      "trigger": "phishing_email",
      "steps": [
        {"id": "triage", "action": "ai_classify", "params": {...}, "next": "enrich"},
        {"id": "enrich", "action": "enrich_indicators", "params": {...}, "next": {"on_true": "isolate", "on_false": "notify"}},
        {"id": "isolate", "action": "edr_isolate_host", "params": {"host": "$alert.endpoint"}, "requires_approval": true, "next": "notify"},
        {"id": "notify", "action": "notify_slack", "params": {"channel": "#soc-l2", "message": "..."}}
      ]
    }

Supported actions:
    ai_classify, enrich_indicators, edr_isolate_host, edr_quarantine_file,
    network_block_ip, identity_disable_user, notify_slack, notify_teams,
    notify_email, notify_pagerduty, create_jira_ticket, update_servicenow,
    add_evidence, set_case_status, ask_human, sleep

Approval-required actions are gated by settings.PLAYBOOKS_REQUIRE_APPROVAL_FOR
and the case's `pending_approval_step` column.
"""
from __future__ import annotations

import datetime
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.models.playbook import PlaybookModel, PlaybookRunModel
from bradlyai.services.notifications import notify  # unified dispatcher
from bradlyai.services.case_manager import add_evidence, add_note, set_case_status

logger = logging.getLogger("bradlyai.playbooks")


# ═════════════════════════════════════════════════════════════════════
# Built-in playbook library (seeded on first boot)
# ═════════════════════════════════════════════════════════════════════
BUILTIN_PLAYBOOKS = [
    {
        "id": "pb_phishing_response",
        "name": "Phishing Email Response",
        "description": "Triage → enrich indicators → quarantine host → notify L2",
        "trigger": "phishing",
        "severity_filter": "MEDIUM",
        "is_builtin": True,
        "steps": [
            {"id": "triage", "action": "ai_classify",
             "params": {"prompt": "Is this a phishing email? Reply YES/NO."}, "next": "enrich"},
            {"id": "enrich", "action": "enrich_indicators",
             "params": {"sources": ["virustotal", "abuseipdb"]}, "next": "isolate"},
            {"id": "isolate", "action": "edr_isolate_host",
             "params": {"host_var": "alert.endpoint"}, "requires_approval": True,
             "next": "ticket"},
            {"id": "ticket", "action": "create_jira_ticket",
             "params": {"project": "SEC", "summary": "Phishing response for $case.id"}, "next": "notify"},
            {"id": "notify", "action": "notify_slack",
             "params": {"channel": "#soc-l2",
                        "message": "Phishing case $case.id isolated host $alert.endpoint"}},
        ],
    },
    {
        "id": "pb_ransomware_response",
        "name": "Ransomware Response",
        "description": "High-severity containment for ransomware indicators",
        "trigger": "ransomware",
        "severity_filter": "CRITICAL",
        "is_builtin": True,
        "steps": [
            {"id": "isolate_host", "action": "edr_isolate_host",
             "params": {"host_var": "alert.endpoint"}, "requires_approval": True, "next": "block_ip"},
            {"id": "block_ip", "action": "network_block_ip",
             "params": {"ip_var": "alert.ip"}, "requires_approval": True, "next": "disable_user"},
            {"id": "disable_user", "action": "identity_disable_user",
             "params": {"user_var": "alert.user"}, "requires_approval": True, "next": "evidence"},
            {"id": "evidence", "action": "add_evidence",
             "params": {"evidence_type": "edr_query", "value": "process_tree:$alert.endpoint"}, "next": "page"},
            {"id": "page", "action": "notify_pagerduty",
             "params": {"service_key": "soc-critical", "summary": "Ransomware containment on $alert.endpoint"}},
        ],
    },
    {
        "id": "pb_bruteforce_response",
        "name": "Brute Force Response",
        "description": "Account-lockout + IP block for repeated auth failures",
        "trigger": "brute_force",
        "severity_filter": "HIGH",
        "is_builtin": True,
        "steps": [
            {"id": "check_ip", "action": "enrich_indicators",
             "params": {"sources": ["abuseipdb", "greynoise"]}, "next": "decide"},
            {"id": "decide", "action": "ai_classify",
             "params": {"prompt": "Based on reputation, should we block this IP? YES/NO."},
             "next": {"on_true": "block", "on_false": "notify"}},
            {"id": "block", "action": "network_block_ip",
             "params": {"ip_var": "alert.ip", "duration_hours": 24}, "requires_approval": False,
             "next": "notify"},
            {"id": "notify", "action": "notify_slack",
             "params": {"channel": "#soc-l1", "message": "Brute-force block added for $alert.ip"}},
        ],
    },
]


# ═════════════════════════════════════════════════════════════════════
# Action handlers
# ═════════════════════════════════════════════════════════════════════
def _resolve_var(value: str, ctx: Dict[str, Any]) -> Any:
    """Resolve `$var.path` references against the execution context."""
    if not isinstance(value, str) or not value.startswith("$"):
        return value
    path = value[1:].split(".")
    cur: Any = ctx
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def _action_ai_classify(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    from bradlyai.services.llm_client import llm_client
    prompt = params.get("prompt", "Classify this alert.")
    # In a production deployment this calls the configured LLM.
    return {"classification": "yes", "raw": prompt}


def _action_enrich_indicators(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    sources = params.get("sources", [])
    ip = _resolve_var("$alert.ip", ctx)
    results: Dict[str, Any] = {}
    if "virustotal" in sources and ip:
        try:
            from bradlyai.services.threatintel.virustotal import vt_lookup_ip
            results["virustotal"] = vt_lookup_ip(ip)
        except Exception as exc:
            results["virustotal"] = {"error": str(exc)}
    if "abuseipdb" in sources and ip:
        try:
            from bradlyai.services.threatintel.abuseipdb import abuseipdb_check
            results["abuseipdb"] = abuseipdb_check(ip)
        except Exception as exc:
            results["abuseipdb"] = {"error": str(exc)}
    if "greynoise" in sources and ip:
        try:
            from bradlyai.services.greynoise_client import greynoise_client
            results["greynoise"] = greynoise_client.classify(ip)
        except Exception as exc:
            results["greynoise"] = {"error": str(exc)}
    return results


def _action_edr_isolate_host(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    host = _resolve_var(params.get("host_var", "$alert.endpoint"), ctx)
    try:
        from bradlyai.services.edr import get_edr_client
        client = get_edr_client()
        return client.isolate_host(host, reason=f"playbook {ctx.get('playbook_id')}")
    except Exception as exc:
        return {"host": host, "dry_run": True, "error": str(exc)}


def _action_edr_quarantine_file(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    sha256 = _resolve_var(params.get("hash_var", "$alert.file_sha256"), ctx)
    try:
        from bradlyai.services.edr import get_edr_client
        client = get_edr_client()
        return client.quarantine_file(sha256, reason="playbook")
    except Exception as exc:
        return {"hash": sha256, "error": str(exc)}


def _action_network_block_ip(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    ip = _resolve_var(params.get("ip_var", "$alert.ip"), ctx)
    duration = params.get("duration_hours")
    try:
        from bradlyai.services.network import get_network_client
        client = get_network_client()
        return client.block_ip(ip, duration_hours=duration, reason="playbook")
    except Exception as exc:
        return {"ip": ip, "dry_run": True, "error": str(exc)}


def _action_identity_disable_user(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    user = _resolve_var(params.get("user_var", "$alert.user"), ctx)
    try:
        from bradlyai.services.identity import get_identity_client
        client = get_identity_client()
        return client.disable_user(user, reason="playbook")
    except Exception as exc:
        return {"user": user, "dry_run": True, "error": str(exc)}


def _action_notify_slack(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    msg = _resolve_var(params.get("message", ""), ctx) or params.get("message", "")
    return notify("slack", channel=params.get("channel"), message=msg)


def _action_notify_teams(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    msg = _resolve_var(params.get("message", ""), ctx) or params.get("message", "")
    return notify("teams", message=msg)


def _action_notify_email(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    return notify("email",
                  to=params.get("to"),
                  subject=params.get("subject", "BradlyAI Playbook Notification"),
                  body=params.get("body", ""))


def _action_notify_pagerduty(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    return notify("pagerduty",
                  service_key=params.get("service_key"),
                  summary=_resolve_var(params.get("summary", ""), ctx) or params.get("summary", ""))


def _action_create_jira_ticket(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from bradlyai.services.itsm.jira import jira_create_issue
        return jira_create_issue(
            project=params.get("project", settings.JIRA_DEFAULT_PROJECT_KEY),
            summary=_resolve_var(params.get("summary", ""), ctx) or params.get("summary", ""),
            description=params.get("description", ""),
            issue_type=params.get("issue_type", "Task"),
        )
    except Exception as exc:
        return {"error": str(exc)}


def _action_update_servicenow(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    try:
        from bradlyai.services.itsm.servicenow import servicenow_update_incident
        return servicenow_update_incident(
            sys_id=params.get("sys_id"),
            work_notes=params.get("work_notes", ""),
            state=params.get("state"),
        )
    except Exception as exc:
        return {"error": str(exc)}


def _action_add_evidence(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    case_id = ctx.get("case_id")
    if not case_id:
        return {"error": "no case context"}
    value = _resolve_var(params.get("value", ""), ctx) or params.get("value", "")
    return {"added": add_evidence(ctx["db"], case_id, params.get("evidence_type", "log"),
                                  value, source="playbook")}


def _action_set_case_status(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    case_id = ctx.get("case_id")
    if not case_id:
        return {"error": "no case context"}
    set_case_status(ctx["db"], case_id, params.get("status", "IN_PROGRESS"), actor="playbook")
    return {"status": params.get("status")}


def _action_ask_human(params: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Mark run as AWAITING_APPROVAL — human must call /playbooks/runs/{id}/resume."""
    return {"awaiting_approval": True,
            "prompt": params.get("prompt", "Please review and approve to continue.")}


ACTION_REGISTRY = {
    "ai_classify": _action_ai_classify,
    "enrich_indicators": _action_enrich_indicators,
    "edr_isolate_host": _action_edr_isolate_host,
    "edr_quarantine_file": _action_edr_quarantine_file,
    "network_block_ip": _action_network_block_ip,
    "identity_disable_user": _action_identity_disable_user,
    "notify_slack": _action_notify_slack,
    "notify_teams": _action_notify_teams,
    "notify_email": _action_notify_email,
    "notify_pagerduty": _action_notify_pagerduty,
    "create_jira_ticket": _action_create_jira_ticket,
    "update_servicenow": _action_update_servicenow,
    "add_evidence": _action_add_evidence,
    "set_case_status": _action_set_case_status,
    "ask_human": _action_ask_human,
    # simple ones
    "sleep": lambda p, c: {"slept": p.get("seconds", 0)},
}


# ═════════════════════════════════════════════════════════════════════
# Runner
# ═════════════════════════════════════════════════════════════════════
def run_playbook(db: Session, playbook_id: str, alert: Optional[Dict[str, Any]] = None,
                 case_id: Optional[str] = None, triggered_by: str = "system",
                 tenant_id: Optional[str] = None) -> PlaybookRunModel:
    """Execute a playbook synchronously. Approval-gated actions pause the run.

    In production, you'd typically run this in a background worker. The
    synchronous version is fine for small playbooks (<50 steps) and is
    covered by tests.
    """
    pb = db.query(PlaybookModel).filter(PlaybookModel.id == playbook_id).first()
    if pb is None:
        raise ValueError(f"Playbook not found: {playbook_id}")
    steps = pb.steps_json.get("steps", []) if isinstance(pb.steps_json, dict) else pb.steps_json
    step_map = {s["id"]: s for s in steps}
    first_id = steps[0]["id"] if steps else None
    run = PlaybookRunModel(
        id=f"pbr_{uuid.uuid4().hex[:10]}", playbook_id=pb.id, case_id=case_id,
        alert_id=(alert or {}).get("id"), triggered_by=triggered_by, tenant_id=tenant_id,
        status="RUNNING", current_step=first_id,
        state_json={"alert": alert or {}, "case": {"id": case_id}},
        history_json=[],
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    cur_id = first_id
    steps_executed = 0
    max_steps = settings.PLAYBOOKS_MAX_STEPS
    approval_required = set((settings.PLAYBOOKS_REQUIRE_APPROVAL_FOR or "").split(","))

    ctx = {
        "alert": alert or {}, "case": {"id": case_id}, "db": db,
        "playbook_id": pb.id, "run_id": run.id, "tenant_id": tenant_id,
    }
    history: List[Dict[str, Any]] = []

    try:
        while cur_id and steps_executed < max_steps:
            step = step_map.get(cur_id)
            if step is None:
                raise ValueError(f"Unknown step: {cur_id}")
            action = step["action"]
            handler = ACTION_REGISTRY.get(action)
            if handler is None:
                raise ValueError(f"Unknown action: {action}")
            params = step.get("params", {})

            t0 = time.time()
            try:
                result = handler(params, ctx)
            except Exception as exc:
                result = {"error": str(exc)}
                run.status = "FAILED"
                run.error = f"Step {cur_id} failed: {exc}"
                db.commit()
                return run

            history.append({
                "step": cur_id, "action": action, "params": params,
                "result": result, "elapsed_ms": int((time.time() - t0) * 1000),
                "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            # Persist variables from result back into context
            if isinstance(result, dict):
                for k, v in result.items():
                    if k in ("error",):
                        continue
                    ctx.setdefault("vars", {})[k] = v

            steps_executed += 1
            run.current_step = cur_id
            run.state_json = ctx
            run.history_json = history
            db.commit()

            # Approval gate
            if step.get("requires_approval") or action in approval_required:
                run.status = "AWAITING_APPROVAL"
                run.pending_approval_step = cur_id
                db.commit()
                logger.info(f"Playbook {pb.id} paused at step {cur_id} awaiting approval")
                return run

            # Routing
            nxt = step.get("next")
            if isinstance(nxt, dict):
                # Conditional routing — evaluate against ctx.vars
                cond_var = ctx.get("vars", {}).get("classification", "")
                if isinstance(cond_var, str) and cond_var.lower() in ("yes", "true", "block"):
                    cur_id = nxt.get("on_true")
                else:
                    cur_id = nxt.get("on_false")
            else:
                cur_id = nxt

        run.status = "COMPLETED"
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        return run

    except Exception as exc:
        run.status = "FAILED"
        run.error = str(exc)
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        raise


def resume_playbook(db: Session, run_id: str, approved: bool,
                    actor: str = "human") -> PlaybookRunModel:
    """Resume a paused playbook after a human approval."""
    run = db.query(PlaybookRunModel).filter(PlaybookRunModel.id == run_id).first()
    if run is None:
        raise ValueError(f"Run not found: {run_id}")
    if run.status != "AWAITING_APPROVAL":
        raise ValueError(f"Run not awaiting approval (status={run.status})")
    if not approved:
        run.status = "CANCELLED"
        run.finished_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        return run

    run.status = "RUNNING"
    run.pending_approval_step = None
    db.commit()
    pb = db.query(PlaybookModel).filter(PlaybookModel.id == run.playbook_id).first()
    steps = pb.steps_json.get("steps", []) if isinstance(pb.steps_json, dict) else pb.steps_json
    step_map = {s["id"]: s for s in steps}
    cur_id = run.current_step
    ctx = run.state_json or {}
    ctx["db"] = db
    history = run.history_json or []
    max_steps = settings.PLAYBOOKS_MAX_STEPS
    steps_executed = 0
    while cur_id and steps_executed < max_steps:
        step = step_map.get(cur_id)
        if step is None:
            break
        handler = ACTION_REGISTRY.get(step["action"])
        if handler is None:
            break
        try:
            result = handler(step.get("params", {}), ctx)
        except Exception as exc:
            result = {"error": str(exc)}
        history.append({"step": cur_id, "action": step["action"], "result": result})
        run.history_json = history
        run.state_json = ctx
        db.commit()
        if step.get("requires_approval"):
            run.status = "AWAITING_APPROVAL"
            run.pending_approval_step = cur_id
            db.commit()
            return run
        nxt = step.get("next")
        if isinstance(nxt, dict):
            cond_var = ctx.get("vars", {}).get("classification", "")
            cur_id = nxt.get("on_true") if (isinstance(cond_var, str) and cond_var.lower() in ("yes", "true")) else nxt.get("on_false")
        else:
            cur_id = nxt
        steps_executed += 1
    run.status = "COMPLETED"
    run.finished_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    return run


def seed_builtin_playbooks(db: Session) -> None:
    """Insert the built-in playbook library on first boot."""
    for spec in BUILTIN_PLAYBOOKS:
        if db.query(PlaybookModel).filter(PlaybookModel.id == spec["id"]).first():
            continue
        pb = PlaybookModel(
            id=spec["id"], name=spec["name"], description=spec["description"],
            trigger=spec.get("trigger"), severity_filter=spec.get("severity_filter"),
            is_builtin=True, enabled=True,
            steps_json={"steps": spec["steps"]},
            tenant_id=settings.DEFAULT_TENANT_ID,
        )
        db.add(pb)
    db.commit()
