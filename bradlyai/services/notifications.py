"""Unified notification dispatcher.

Routes alerts/events to Slack, Teams, PagerDuty, Email, or generic webhook.
All sinks default to DRY-RUN (logs the payload) unless explicitly enabled
in settings — this keeps the platform safe in production by default.
"""
from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, Optional

import httpx

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.notifications")


@dataclass
class NotificationResult:
    channel: str
    success: bool
    detail: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


def notify(channel: str, **kwargs) -> Dict[str, Any]:
    """Top-level dispatcher. channel ∈ {slack, teams, pagerduty, email, webhook}.

    Returns a dict with {channel, success, detail, extra}.
    """
    handler = {
        "slack": _send_slack,
        "teams": _send_teams,
        "pagerduty": _send_pagerduty,
        "email": _send_email,
        "webhook": _send_webhook,
    }.get(channel.lower())
    if handler is None:
        return NotificationResult(channel=channel, success=False,
                                  detail=f"Unknown channel: {channel}").__dict__
    try:
        return handler(**kwargs).__dict__
    except Exception as exc:
        logger.exception(f"Notification {channel} failed")
        return NotificationResult(channel=channel, success=False, detail=str(exc)).__dict__


# ── Slack ──────────────────────────────────────────────────────────────
def _send_slack(message: str, channel: Optional[str] = None,
                blocks: Optional[list] = None) -> NotificationResult:
    if not settings.SLACK_ENABLED:
        return NotificationResult("slack", True, detail="dry-run (SLACK_ENABLED=false)",
                                  extra={"would_post": {"channel": channel or settings.SLACK_DEFAULT_CHANNEL,
                                                        "text": message}})
    payload = {"channel": channel or settings.SLACK_DEFAULT_CHANNEL, "text": message}
    if blocks:
        payload["blocks"] = blocks
    try:
        r = httpx.post("https://slack.com/api/chat.postMessage",
                       headers={"Authorization": f"Bearer {settings.SLACK_BOT_TOKEN}",
                                "Content-Type": "application/json; charset=utf-8"},
                       json=payload, timeout=10)
        data = r.json()
        return NotificationResult("slack", data.get("ok", False), detail=str(data))
    except Exception as exc:
        return NotificationResult("slack", False, detail=str(exc))


# ── Microsoft Teams (Incoming Webhook) ────────────────────────────────
def _send_teams(message: str, title: Optional[str] = None,
                color: str = "FF0000") -> NotificationResult:
    if not settings.TEAMS_ENABLED or not settings.TEAMS_WEBHOOK_URL:
        return NotificationResult("teams", True, detail="dry-run (TEAMS_ENABLED=false)",
                                  extra={"would_post": {"title": title, "text": message}})
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": title or "BradlyAI Alert",
        "title": title or "BradlyAI Alert",
        "text": message,
    }
    try:
        r = httpx.post(settings.TEAMS_WEBHOOK_URL, json=payload, timeout=10)
        return NotificationResult("teams", r.status_code in (200, 204),
                                  detail=f"HTTP {r.status_code}")
    except Exception as exc:
        return NotificationResult("teams", False, detail=str(exc))


# ── PagerDuty Events API v2 ───────────────────────────────────────────
def _send_pagerduty(summary: str, severity: str = "warning",
                    source: str = "bradlyai", service_key: Optional[str] = None,
                    custom_details: Optional[Dict[str, Any]] = None) -> NotificationResult:
    if not settings.PAGERDUTY_ENABLED:
        return NotificationResult("pagerduty", True, detail="dry-run (PAGERDUTY_ENABLED=false)",
                                  extra={"would_post": {"summary": summary, "severity": severity}})
    routing_key = service_key or settings.PAGERDUTY_INTEGRATION_KEY
    if not routing_key:
        return NotificationResult("pagerduty", False, detail="Missing PAGERDUTY_INTEGRATION_KEY")
    payload = {
        "routing_key": routing_key, "event_action": "trigger",
        "payload": {"summary": summary, "severity": severity, "source": source,
                    "custom_details": custom_details or {}},
    }
    try:
        r = httpx.post("https://events.pagerduty.com/v2/enqueue", json=payload, timeout=10)
        return NotificationResult("pagerduty", r.status_code == 202,
                                  detail=f"HTTP {r.status_code} body={r.text[:200]}")
    except Exception as exc:
        return NotificationResult("pagerduty", False, detail=str(exc))


# ── Email (SMTP) ──────────────────────────────────────────────────────
def _send_email(to: str, subject: str, body: str,
                html_body: Optional[str] = None) -> NotificationResult:
    if not settings.EMAIL_ENABLED:
        return NotificationResult("email", True, detail="dry-run (EMAIL_ENABLED=false)",
                                  extra={"would_send": {"to": to, "subject": subject}})
    if not settings.EMAIL_SMTP_HOST:
        return NotificationResult("email", False, detail="EMAIL_SMTP_HOST not configured")
    msg = MIMEMultipart("alternative") if html_body else MIMEText(body, "plain")
    msg["From"] = settings.EMAIL_FROM_ADDRESS
    msg["To"] = to
    msg["Subject"] = subject
    if html_body:
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html_body, "html"))
    try:
        with smtplib.SMTP(settings.EMAIL_SMTP_HOST, settings.EMAIL_SMTP_PORT, timeout=15) as s:
            if settings.EMAIL_SMTP_USE_TLS:
                s.starttls()
            if settings.EMAIL_SMTP_USERNAME:
                s.login(settings.EMAIL_SMTP_USERNAME, settings.EMAIL_SMTP_PASSWORD)
            s.sendmail(settings.EMAIL_FROM_ADDRESS, [to], msg.as_string())
        return NotificationResult("email", True, detail=f"Sent to {to}")
    except Exception as exc:
        return NotificationResult("email", False, detail=str(exc))


# ── Generic webhook ───────────────────────────────────────────────────
def _send_webhook(url: Optional[str] = None, payload: Optional[Dict[str, Any]] = None) -> NotificationResult:
    target = url or settings.WEBHOOK_NOTIFY_URL
    if not settings.WEBHOOK_NOTIFY_ENABLED or not target:
        return NotificationResult("webhook", True, detail="dry-run (WEBHOOK_NOTIFY_ENABLED=false)",
                                  extra={"would_post": payload})
    try:
        r = httpx.post(target, json=payload or {}, timeout=10)
        return NotificationResult("webhook", r.status_code in (200, 201, 202, 204),
                                  detail=f"HTTP {r.status_code}")
    except Exception as exc:
        return NotificationResult("webhook", False, detail=str(exc))


# ═════════════════════════════════════════════════════════════════════
# Convenience: alert-to-notification helper used by L1 Agent
# ═════════════════════════════════════════════════════════════════════
def escalate_to_l2(alert: Dict[str, Any], reason: str,
                   channels: Optional[list] = None) -> Dict[str, Any]:
    """Send an L2 escalation across the requested channels (default: all enabled)."""
    enabled_channels = channels or []
    if not enabled_channels:
        if settings.SLACK_ENABLED:
            enabled_channels.append("slack")
        if settings.TEAMS_ENABLED:
            enabled_channels.append("teams")
        if settings.PAGERDUTY_ENABLED and alert.get("severity") in ("CRITICAL", "HIGH"):
            enabled_channels.append("pagerduty")
        if settings.EMAIL_ENABLED:
            enabled_channels.append("email")
    if not enabled_channels:
        # Dry-run to slack channel
        enabled_channels = ["slack"]

    summary = f"[{alert.get('severity','?')}] {alert.get('title','Alert')} — {reason}"
    custom = {"alert_id": alert.get("id"), "endpoint": alert.get("endpoint"),
              "ip": alert.get("ip"), "mitre": alert.get("mitre")}
    results = {}
    for ch in enabled_channels:
        if ch == "slack":
            results[ch] = notify("slack", message=summary, channel=settings.SLACK_L2_CHANNEL)
        elif ch == "teams":
            results[ch] = notify("teams", message=summary, title="BradlyAI L2 Escalation", color="FF0000")
        elif ch == "pagerduty":
            results[ch] = notify("pagerduty", summary=summary,
                                 severity="critical" if alert.get("severity") == "CRITICAL" else "warning",
                                 custom_details=custom)
        elif ch == "email":
            body = json.dumps({"alert": alert, "reason": reason}, indent=2)
            results[ch] = notify("email", to=settings.EMAIL_L2_DISTRIBUTION_LIST,
                                 subject=f"BradlyAI Escalation: {alert.get('id')}",
                                 body=body)
    return {"summary": summary, "results": results}
