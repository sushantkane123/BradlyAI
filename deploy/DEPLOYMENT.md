# BradlyAI — Deployment Guide

Production deployment for the BradlyAI SOC platform. Supports three modes: **native**, **Docker**, and **systemd**.

## At a glance

| Mode | Best for | Auto-restart | Persistent DB | TLS |
|------|----------|--------------|---------------|-----|
| **native** (this repo) | Quick local / dev server | Crash loop | Local volume | Manual |
| **Docker** | Reproducible, isolated prod | `restart: unless-stopped` | Named volume | via reverse proxy |
| **systemd** | Bare-metal Linux server | `Restart=always` | Local dir | via reverse proxy |

---

## Mode A — Native (simplest)

```bash
# 1. One-shot install
./deploy/install.sh

# 2. (optional) edit .env to add API keys
nano .env

# 3. Start (binds 0.0.0.0:8000)
./deploy/start.sh

# 4. Verify
./deploy/status.sh
curl http://localhost:8000/health

# 5. Tail logs
tail -f logs/bradlyai.log

# 6. Stop
./deploy/stop.sh
```

The dashboard is now accessible at:
- `http://localhost:8000/` (this machine)
- `http://<your-LAN-IP>:8000/` (any device on the same network)

### Windows users — pick your shell

The `deploy/` directory ships with **four** script families so you don't need Git Bash:

| Shell | Install | Start | Stop | Status |
|-------|---------|-------|------|--------|
| **cmd.exe** | `deploy\install.bat` | `deploy\start.bat` | `deploy\stop.bat` | `deploy\status.bat` |
| **PowerShell** | `.\deploy\install.ps1` | `.\deploy\start.ps1` | `.\deploy\stop.ps1` | `.\deploy\status.ps1` |
| **Git Bash** (if installed) | `./deploy/install.sh` | `./deploy/start.sh` | `./deploy/stop.sh` | `./deploy/status.sh` |
| **WSL** (if installed) | `./deploy/install.sh` | `./deploy/start.sh` | `./deploy/stop.sh` | `./deploy/status.sh` |

PowerShell example (recommended for Windows):
```powershell
# Run from project root
.\deploy\install.ps1
.\deploy\start.ps1
# Open http://localhost:8000
.\deploy\status.ps1   # check health
.\deploy\stop.ps1     # stop
```

cmd.exe example:
```cmd
deploy\install.bat
deploy\start.bat
REM open http://localhost:8000
deploy\status.bat
deploy\stop.bat
```

If PowerShell blocks the script, run once:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Prerequisites on Windows:**
- Python 3.10+ from https://www.python.org/downloads/ (tick "Add Python to PATH")
- That's it — no Git Bash, no WSL, no Docker required

---

## Mode B — Docker

```bash
# 1. Build & run (foreground)
docker compose up -d --build

# 2. Verify
docker compose ps
docker compose logs -f bradlyai
curl http://localhost:8000/health

# 3. Stop
docker compose down

# 4. Wipe everything (incl. DB)
docker compose down -v
```

The Docker build uses a multi-stage approach with a Python 3.11 slim base, runs as non-root, and persists SQLite to the `bradlyai_data` named volume. A `HEALTHCHECK` hits `/health` every 30 s.

Pass API keys via `.env` at the project root, or inline:

```bash
GROQ_API_KEY=gsk_xxx docker compose up -d
```

---

## Mode C — systemd (bare metal)

For a real Linux server (Ubuntu/Debian/CentOS/RHEL).

```bash
# 1. Create a dedicated user
sudo useradd --system --shell /bin/false --home /opt/bradlyai bradlyai

# 2. Install the app
sudo mkdir -p /opt/bradlyai
sudo cp -r . /opt/bradlyai/
sudo chown -R bradlyai:bradlyai /opt/bradlyai
sudo -u bradlyai /opt/bradlyai/deploy/install.sh

# 3. Install the service unit
sudo cp /opt/bradlyai/deploy/bradlyai.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bradlyai

# 4. Verify
sudo systemctl status bradlyai
curl http://localhost:8000/health
sudo journalctl -u bradlyai -f

# 5. Stop / disable
sudo systemctl stop bradlyai
sudo systemctl disable bradlyai
```

---

## Reverse proxy + TLS

For HTTPS, put Nginx or Caddy in front. Example configs:

- **Nginx** — `deploy/nginx.conf.example` (with Let's Encrypt snippet)
- **Caddy** — one-liner: `caddy reverse-proxy --from bradlyai.example.com --to localhost:8000`

Get free TLS certs from Let's Encrypt:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d bradlyai.example.com
```

---

## Database — SQLite vs Postgres

The default is **SQLite** at `data/bradlyai_soc.db`. This is fine for single-host deployments with modest alert volumes (< 10k alerts/day).

For higher throughput, multi-host, or HA, migrate to Postgres:

1. Provision a Postgres (e.g. Neon, Supabase, Render, RDS)
2. Update `.env`:
   ```
   DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/bradlyai
   ```
3. Install the driver: `pip install asyncpg`
4. Re-run `./deploy/start.sh`

---

## Monitoring the deployment

| Signal | Where |
|--------|-------|
| Process state | `./deploy/status.sh` |
| Health probe | `curl http://host:8000/health` |
| Swagger docs | `http://host:8000/docs` |
| Live logs | `tail -f logs/bradlyai.log` (native) or `docker compose logs -f` |
| Crash restarts | systemd journal (`journalctl -u bradlyai`) or Docker restart count |

The `/health` endpoint returns:

```json
{
  "status": "healthy",
  "app": "BradlyAI - Driverless SOC & Automated Incident Response",
  "version": "2.1.0-PRO",
  "environment": "production",
  "database": "connected",
  "worker_active": true,
  "uptime": "2026-06-22 07:30:00 UTC"
}
```

Set up an external monitor (UptimeRobot, Grafana, Nagios) to ping `/health` every 60 s.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Address already in use` | Port 8000 taken | `./deploy/start.sh --port 8001` or `sudo lsof -i :8000` |
| `/health` returns `degraded` | DB not writable | Check `data/` permissions |
| AI Copilot returns errors | No API key | Set `GROQ_API_KEY` or `OPENAI_API_KEY` in `.env` |
| SQLite locked errors | Multi-writer | Stick to `workers=1` (already the default) |
| WebSocket disconnects | Behind proxy w/o upgrade headers | Configure `proxy_set_header Upgrade $http_upgrade;` |

---

## Architecture diagram

```
        ┌─────────────────────────────────────────┐
        │  Browser / SOC Analyst                  │
        │  (Chrome / Firefox / Edge)              │
        └─────────────┬───────────────────────────┘
                      │ HTTPS (TLS termination)
                      ▼
        ┌─────────────────────────────────────────┐
        │  Nginx / Caddy (optional reverse proxy) │
        │  - TLS termination                      │
        │  - Security headers                     │
        │  - Static asset caching                 │
        └─────────────┬───────────────────────────┘
                      │ http (127.0.0.1:8000)
                      ▼
   ┌──────────────────────────────────────────────┐
   │  BradlyAI (FastAPI + Uvicorn / Gunicorn)     │
   │                                              │
   │  ┌────────────┐  ┌────────────────────────┐ │
   │  │ Static SPA │  │ REST API               │ │
   │  │ (HTML/JS)  │  │  • /health             │ │
   │  └────────────┘  │  • /api/v1/alerts      │ │
   │                  │  • /api/v1/incidents   │ │
   │                  │  • /api/v1/asm/*       │ │
   │                  │  • /api/v1/mitre/*     │ │
   │                  │  • /api/v1/chat        │ │
   │                  │  • /api/v1/integration │ │
   │                  │  • /api/v1/ws/stream   │ │
   │                  └────────────────────────┘ │
   │                                              │
   │  ┌────────────────┐  ┌──────────────────┐  │
   │  │ Background     │  │ AI Engine         │  │
   │  │ telemetry      │  │ (OpenAI / Groq)   │  │
   │  │ worker         │  └──────────────────┘  │
   │  └────────────────┘                         │
   └──────────┬───────────────────────────────────┘
              │
              ▼
     ┌─────────────────────┐
     │  SQLite / Postgres  │
     │  bradlyai_soc.db    │
     └─────────────────────┘
```

---

## Security checklist (production)

- [ ] Change default API keys; rotate periodically
- [ ] Front the service with TLS (Nginx/Caddy)
- [ ] Restrict `CORS_ALLOWED_ORIGINS` to your domain
- [ ] Run as non-root user (systemd unit already does this)
- [ ] Enable `RATE_LIMIT_ENABLED=true` (default)
- [ ] Set up log rotation: `/etc/logrotate.d/bradlyai`
- [ ] Back up `data/bradlyai_soc.db` daily
- [ ] Monitor `/health` with external uptime service
- [ ] Keep `pip` dependencies updated: `pip install -U -r requirements.txt`
- [ ] Subscribe to BradlyAI security advisories
