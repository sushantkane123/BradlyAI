# ============================================================================
# BradlyAI — Gunicorn production config
# Used by: ./deploy/start.sh --gunicorn
#
# Notes:
# - SQLite needs a single writer → workers=1, threads=N for concurrency
# - For high traffic, migrate to PostgreSQL + workers=N
# ============================================================================
import multiprocessing
import os

bind = f"{os.getenv('HOST', '0.0.0.0')}:{os.getenv('PORT', '8000')}"

# Workers: SQLite is single-writer, so keep at 1 (use threads for I/O concurrency)
workers = int(os.getenv("GUNICORN_WORKERS", "1"))
threads = int(os.getenv("GUNICORN_THREADS", "4"))
worker_class = "gthread"

# Worker recycling
max_requests = 1000
max_requests_jitter = 50
preload_app = True

# Timeouts
timeout = 60
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
access_log_format = '%(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sus'

# Process name
proc_name = "bradlyai_soc"

# Security
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190
