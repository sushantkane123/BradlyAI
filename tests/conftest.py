"""Deterministic, isolated defaults for the test suite.

Production defaults intentionally do not seed demo records or create a known
administrator. Tests opt into fixtures before application modules are imported.
A unique temporary SQLite database prevents local development data (and a prior
pytest run) from changing test outcomes.
"""
import os
import tempfile
from pathlib import Path

_test_db = Path(tempfile.gettempdir()) / f"bradlyai-pytest-{os.getpid()}.db"
for suffix in ("", "-wal", "-shm"):
    try:
        _test_db.with_name(_test_db.name + suffix).unlink()
    except FileNotFoundError:
        pass

# Deliberately assign rather than setdefault: OS variables take precedence over
# .env in Pydantic settings, which keeps pytest separate from a developer's DB.
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_test_db.as_posix()}"
os.environ["ENVIRONMENT"] = "test"
os.environ["DEMO_DATA_ENABLED"] = "true"
os.environ["LIVE_SIMULATION_WORKER_ACTIVE"] = "false"
os.environ["BOOTSTRAP_ADMIN_USERNAME"] = "admin"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = "admin@test.local"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "Admin123!ChangeMe"
