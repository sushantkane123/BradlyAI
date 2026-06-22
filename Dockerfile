# BradlyAI — Production Dockerfile
# Python 3.11 slim base image
FROM python:3.11-slim

# Prevent .pyc files and force unbuffered stdout/stderr for live logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app \
    PIP_NO_CACHE_DIR=1

# Set work directory
WORKDIR $APP_HOME

# Install system dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (cached as separate layer)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the entire project (excluding .git, venv, caches)
COPY . .

# Persistent directory for SQLite DB & logs
RUN mkdir -p /app/data /app/logs

# Healthcheck hits the /health endpoint every 30s
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# Expose the FastAPI port
EXPOSE 8000

# Production launch via uvicorn (single worker; SQLite needs single writer)
CMD ["uvicorn", "bradlyai.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--log-level", "info"]
