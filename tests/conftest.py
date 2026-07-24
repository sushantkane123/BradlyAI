"""Deterministic, isolated defaults for the test suite.

Production defaults intentionally do not seed demo records or create a known
administrator. Tests opt into fixtures before application modules are imported.
"""
import os

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DEMO_DATA_ENABLED", "true")
os.environ.setdefault("LIVE_SIMULATION_WORKER_ACTIVE", "false")
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "admin")
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "Admin123!ChangeMe")
