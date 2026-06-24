"""Prometheus metrics + OpenTelemetry tracing setup.

All BradlyAI metrics live here so they're consistently labelled and easy
to extend. Exposed via /metrics (see metrics router).
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Optional

from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry, REGISTRY

logger = logging.getLogger("bradlyai.metrics")


# ── Counters ──
ALERTS_RECEIVED = Counter(
    "bradlyai_alerts_received_total",
    "Total alerts received by source",
    ["source"],
)
ALERTS_CLOSED = Counter(
    "bradlyai_alerts_closed_total",
    "Alerts auto-closed by the L1 agent",
    ["reason", "decision"],
)
ALERTS_ESCALATED = Counter(
    "bradlyai_alerts_escalated_total",
    "Alerts escalated to L2",
    ["reason"],
)
LLM_CALLS = Counter(
    "bradlyai_llm_calls_total",
    "LLM API calls",
    ["provider", "result"],
)
NOTIFICATIONS_SENT = Counter(
    "bradlyai_notifications_sent_total",
    "Notifications dispatched",
    ["channel", "success"],
)
PLAYBOOK_RUNS = Counter(
    "bradlyai_playbook_runs_total",
    "Playbook run outcomes",
    ["playbook_id", "status"],
)
CASES_CREATED = Counter(
    "bradlyai_cases_created_total",
    "Cases created",
    ["severity"],
)
SLA_BREACHES = Counter(
    "bradlyai_sla_breaches_total",
    "Cases that breached SLA",
    ["priority"],
)
EDR_ACTIONS = Counter(
    "bradlyai_edr_actions_total",
    "EDR actions executed",
    ["provider", "action", "dry_run"],
)
NETWORK_ACTIONS = Counter(
    "bradlyai_network_actions_total",
    "Network containment actions",
    ["provider", "action", "dry_run"],
)
IDENTITY_ACTIONS = Counter(
    "bradlyai_identity_actions_total",
    "Identity/IAM actions",
    ["provider", "action", "dry_run"],
)

# ── Gauges ──
OPEN_CASES = Gauge(
    "bradlyai_open_cases",
    "Currently open cases",
    ["priority"],
)
DECISION_CONFIDENCE = Histogram(
    "bradlyai_decision_confidence",
    "Distribution of L1 Agent decision confidence",
    buckets=(0.1, 0.3, 0.5, 0.7, 0.85, 0.9, 0.95, 0.99, 1.0),
)
DETECTION_ENGINE_LATENCY = Histogram(
    "bradlyai_detection_engine_latency_seconds",
    "Time spent running detection engine per alert",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
ACTIVE_WORKERS = Gauge(
    "bradlyai_active_workers",
    "Background workers currently active",
    ["name"],
)


# ── Convenience helpers ──
@contextmanager
def measure_latency(histogram: Histogram, **labels):
    start = time.perf_counter()
    try:
        yield
    finally:
        histogram.labels(**labels).observe(time.perf_counter() - start)


def llm_call(provider: str, success: bool):
    LLM_CALLS.labels(provider=provider, result="success" if success else "error").inc()


def record_decision(confidence: float):
    DECISION_CONFIDENCE.observe(confidence)


def track_active_worker(name: str, active: bool):
    ACTIVE_WORKERS.labels(name=name).set(1 if active else 0)


def install_otel_if_configured(app):
    """Wire OpenTelemetry tracing if OTEL_ENABLED=true. No-op otherwise."""
    if not __import__("bradlyai").config.settings.OTEL_ENABLED:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint=__import__("bradlyai").config.settings.OTEL_EXPORTER_OTLP_ENDPOINT)
        ))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        logger.info("OpenTelemetry tracing enabled")
    except Exception as exc:
        logger.warning(f"OTel setup failed (continuing without): {exc}")
