"""BradlyAI - Driverless SOC & Automated Incident Response Application Entrypoint"""
import logging
import time
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.database import engine, Base, SessionLocal
from bradlyai.models.alert import AlertModel, AlertStorylineModel
from bradlyai.models.asset import AssetModel, AssetFindingModel
from bradlyai.routers import (
    alerts, asm, air, forensics, mitre, chat, ws, system, ingest,
    integration, l1_agent,
    # NEW competitive-hardening routers
    auth, notifications, edr, network, identity, itsm,
    threatintel, sigma, cases, playbooks, reports, metrics,
)
from bradlyai.services.live_simulation_worker import live_worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bradlyai")


def seed_database():
    db = SessionLocal()
    try:
        if db.query(AlertModel).count() == 0:
            logger.info("🌱 Seeding default BradlyAI security alerts to database...")
            default_alerts = [
                {"id": "ALT-8921", "severity": "CRITICAL", "title": "Suspicious Powershell Execution & Registry Modification",
                 "endpoint": "DEV-WIN-SRV09", "ip": "192.168.10.45", "timestamp": "2 mins ago",
                 "mitre": "T1059.001 - PowerShell", "status": "Auto-Contained", "ai_confidence": "98%",
                 "storyline": [
                     {"time": "14:02:11", "event": "User 'svc_jenkins' logged in from unusual IP (45.33.12.9)"},
                     {"time": "14:02:15", "event": "Spawned hidden PowerShell process with encoded command"},
                     {"time": "14:02:18", "event": "Attempted LSASS memory dump for credential harvesting"},
                     {"time": "14:02:19", "event": "BradlyAI detected behavior, killed process, and isolated network interface"},
                 ]},
                {"id": "ALT-8920", "severity": "HIGH", "title": "Unauthorized Lateral Movement via SMB Exploitation",
                 "endpoint": "FIN-WRK-102", "ip": "192.168.20.12", "timestamp": "14 mins ago",
                 "mitre": "T1210 - Exploitation of Remote Services", "status": "Auto-Contained", "ai_confidence": "95%",
                 "storyline": [
                     {"time": "13:50:01", "event": "High volume of SMB authentication requests to Domain Controller"},
                     {"time": "13:50:04", "event": "Anomalous service creation detected on remote host"},
                     {"time": "13:50:06", "event": "BradlyAIR triggered local firewall lockdown and revoked active Kerberos tickets"},
                 ]},
                {"id": "ALT-8919", "severity": "HIGH", "title": "Exfiltration Attempt to Known Tor Exit Node",
                 "endpoint": "ENG-MAC-404", "ip": "192.168.15.88", "timestamp": "32 mins ago",
                 "mitre": "T1048 - Exfiltration Over Alternative Protocol", "status": "Investigating", "ai_confidence": "91%",
                 "storyline": [
                     {"time": "13:32:10", "event": "Encrypted DNS tunnel established to external domain 'xn--x-9b.com'"},
                     {"time": "13:32:45", "event": "540MB of archive files staged in /tmp/staging_cache"},
                     {"time": "13:33:00", "event": "BradlyAIR blocked external IP at gateway and flagged for analyst review"},
                 ]},
                {"id": "ALT-8918", "severity": "MEDIUM", "title": "Anomalous Cloud IAM Policy Privilege Escalation",
                 "endpoint": "AWS-IAM-US-EAST", "ip": "54.210.85.12", "timestamp": "1 hour ago",
                 "mitre": "T1078 - Valid Accounts", "status": "Resolved", "ai_confidence": "89%",
                 "storyline": [
                     {"time": "12:55:20", "event": "DevOps key attempted to attach 'AdministratorAccess' to 'svc_billing_read'"},
                     {"time": "12:55:22", "event": "BradlyAI Cloud AI intercepted API call via AWS EventBridge and rolled back IAM policy"},
                 ]},
            ]
            for alt in default_alerts:
                db_alt = AlertModel(id=alt["id"], severity=alt["severity"], title=alt["title"],
                                    endpoint=alt["endpoint"], ip=alt["ip"], timestamp=alt["timestamp"],
                                    mitre=alt["mitre"], status=alt["status"], ai_confidence=alt["ai_confidence"])
                for st in alt["storyline"]:
                    db_alt.storyline.append(AlertStorylineModel(time=st["time"], event=st["event"]))
                db.add(db_alt)

        if db.query(AssetModel).count() == 0:
            logger.info("🌱 Seeding default ASM assets...")
            default_assets = [
                {"name": "core-auth-api.bradlyai.internal", "type": "Web Service", "ip": "192.168.1.10",
                 "owner": "DevOps Team", "risk_score": "Low (12)", "vulnerabilities": 0, "status": "Secure",
                 "last_scan": "10 mins ago", "findings": []},
                {"name": "aws-s3-customer-backups-prod", "type": "Cloud Storage", "ip": "s3.amazonaws.com",
                 "owner": "Cloud Ops", "risk_score": "Critical (91)", "vulnerabilities": 2, "status": "At Risk",
                 "last_scan": "2 mins ago", "findings": ["Public Read Access Enabled", "MFA Delete Disabled"]},
                {"name": "vpn-gateway-apac.bradlyai.com", "type": "Network Gateway", "ip": "203.0.113.45",
                 "owner": "IT Sec", "risk_score": "High (74)", "vulnerabilities": 1, "status": "Vulnerable",
                 "last_scan": "1 hour ago", "findings": ["Unpatched CVE-2024-3400 (SSL-VPN)"]},
                {"name": "win-srv-sql-primary", "type": "Database Server", "ip": "192.168.10.2",
                 "owner": "DBA Team", "risk_score": "Medium (45)", "vulnerabilities": 3, "status": "Monitored",
                 "last_scan": "30 mins ago", "findings": ["SMBv1 Enabled", "Missing Security Patch KB5034441"]},
            ]
            for ast in default_assets:
                db_ast = AssetModel(name=ast["name"], type=ast["type"], ip=ast["ip"], owner=ast["owner"],
                                    risk_score=ast["risk_score"], vulnerabilities=ast["vulnerabilities"],
                                    status=ast["status"], last_scan=ast["last_scan"])
                for f in ast["findings"]:
                    db_ast.findings.append(AssetFindingModel(finding_text=f))
                db.add(db_ast)
        db.commit()
        logger.info("✅ Database seeding complete.")
    finally:
        db.close()


# ── Ensure tables + columns exist (handles existing DBs with new columns) ──
from bradlyai.migrations import run_migrations_and_create
result = run_migrations_and_create(engine, Base)
if result["count"] > 0:
    logger.info(f"🔧 Migrated {result['count']} columns: {', '.join(result['added_columns'])}")
seed_database()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.LIVE_SIMULATION_WORKER_ACTIVE:
        live_worker.start(ws_manager=ws.manager, interval=settings.SIMULATION_INTERVAL_SECONDS)

    # Seed defaults — idempotent
    try:
        from bradlyai.services.whitelist import seed_defaults as seed_whitelist
        seed_whitelist()
    except Exception as e:
        logger.warning(f"Could not seed L1 Agent whitelist: {e}")
    try:
        from bradlyai.services.bootstrap import run_all as run_bootstrap
        from bradlyai.database import SessionLocal
        run_bootstrap(SessionLocal())
    except Exception as e:
        logger.warning(f"Could not seed defaults: {e}")

    logger.info(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} started — Env: {settings.ENVIRONMENT}")
    yield
    live_worker.stop()
    logger.info("🛑 BradlyAI shut down gracefully.")


app = FastAPI(
    title=settings.APP_NAME, version=settings.APP_VERSION,
    description="BradlyAI multi-model machine learning mesh backend API providing automated incident response and a true Driverless SOC experience.",
    docs_url="/docs", redoc_url="/redoc", lifespan=lifespan,
)


# ── Observability ───────────────────────────────────────────────────────
from bradlyai.services.metrics import install_otel_if_configured
install_otel_if_configured(app)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    response.headers["X-Autonomous-SOC"] = "BradlyAI Multi-Model Active Engine"
    return response


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={
        "error_code": "BRADLY_API_EXCEPTION", "message": exc.detail,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    })


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content={
        "error_code": "BRADLY_VALIDATION_ERROR",
        "message": "The request payload failed multi-model cyber schema verification.",
        "details": exc.errors(),
    })


app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ALLOWED_ORIGINS, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

api_prefix = "/api/v1"

# Original routers
app.include_router(alerts.router, prefix=api_prefix)
app.include_router(asm.router, prefix=api_prefix)
app.include_router(air.router, prefix=api_prefix)
app.include_router(forensics.router, prefix=api_prefix)
app.include_router(mitre.router, prefix=api_prefix)
app.include_router(chat.router, prefix=api_prefix)
app.include_router(ingest.router, prefix=api_prefix)
app.include_router(integration.router, prefix=api_prefix)
app.include_router(ws.router, prefix=api_prefix)
app.include_router(system.router, prefix=api_prefix)
app.include_router(l1_agent.router, prefix=api_prefix)

# NEW competitive-hardening routers
app.include_router(auth.router, prefix=api_prefix)
app.include_router(notifications.router, prefix=api_prefix)
app.include_router(edr.router, prefix=api_prefix)
app.include_router(network.router, prefix=api_prefix)
app.include_router(identity.router, prefix=api_prefix)
app.include_router(itsm.router, prefix=api_prefix)
app.include_router(threatintel.router, prefix=api_prefix)
app.include_router(sigma.router, prefix=api_prefix)
app.include_router(cases.router, prefix=api_prefix)
app.include_router(playbooks.router, prefix=api_prefix)
app.include_router(reports.router, prefix=api_prefix)
app.include_router(metrics.router)


@app.get("/health", tags=["Health"])
def health_check():
    db_ok = False
    try:
        db = SessionLocal()
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        db.close()
        db_ok = True
    except Exception:
        pass
    return {
        "status": "healthy" if db_ok else "degraded",
        "app": settings.APP_NAME, "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT, "database": "connected" if db_ok else "disconnected",
        "worker_active": live_worker.is_running,
        "auth_enabled": settings.AUTH_ENABLED,
        "uptime": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def serve_frontend_portal():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/style.css")
def serve_css():
    return FileResponse(os.path.join(STATIC_DIR, "style.css"))


@app.get("/app.js")
def serve_js():
    return FileResponse(os.path.join(STATIC_DIR, "app.js"))


@app.get("/data.js")
def serve_data_js():
    return FileResponse(os.path.join(STATIC_DIR, "data.js"))
