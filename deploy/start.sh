#!/usr/bin/env bash
# ============================================================================
# BradlyAI — Production starter
# Runs the FastAPI service in the background with:
#   • Auto-restart on crash (simple crash loop, capped)
#   • Persistent logs at logs/bradlyai.log
#   • Persistent SQLite DB at data/bradlyai_soc.db
#   • Binds 0.0.0.0:8000 (accessible on your LAN)
#   • PID file at deploy/bradlyai.pid
#
# Usage:
#   ./deploy/start.sh              # start (idempotent)
#   ./deploy/start.sh --foreground # run in foreground (debug)
#   ./deploy/start.sh --gunicorn   # use gunicorn instead of uvicorn
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PID_FILE="${SCRIPT_DIR}/bradlyai.pid"
LOG_DIR="${ROOT_DIR}/logs"
DATA_DIR="${ROOT_DIR}/data"
LOG_FILE="${LOG_DIR}/bradlyai.log"
MAX_RESTARTS=10
RESTART_WINDOW_SEC=300  # 5 minutes

mkdir -p "${LOG_DIR}" "${DATA_DIR}"

# ---- Parse args ----
FOREGROUND=0
USE_GUNICORN=0
for arg in "$@"; do
  case "${arg}" in
    --foreground|-f) FOREGROUND=1 ;;
    --gunicorn|-g)   USE_GUNICORN=1 ;;
    --help|-h)
      sed -n '2,16p' "$0"
      exit 0 ;;
    *) echo "Unknown arg: ${arg}" >&2; exit 1 ;;
  esac
done

# ---- Already running? ----
if [[ -f "${PID_FILE}" ]]; then
  OLD_PID=$(cat "${PID_FILE}")
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    echo "✅ BradlyAI already running (PID ${OLD_PID}). Stop it first with ./deploy/stop.sh"
    exit 0
  else
    echo "⚠️  Stale PID file (PID ${OLD_PID} not alive). Cleaning up."
    rm -f "${PID_FILE}"
  fi
fi

# ---- Activate venv (preferred) ----
if [[ -f "${ROOT_DIR}/venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/venv/bin/activate"
elif [[ -f "${ROOT_DIR}/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.venv/bin/activate"
fi

# ---- Pre-flight env ----
export ENVIRONMENT="${ENVIRONMENT:-production}"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-8000}"
export DATABASE_URL="${DATABASE_URL:-sqlite+aiosqlite:///${DATA_DIR}/bradlyai_soc.db}"

cd "${ROOT_DIR}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# ---- Foreground mode (for debugging) ----
if [[ "${FOREGROUND}" == "1" ]]; then
  log "Starting BradlyAI in FOREGROUND (env=${ENVIRONMENT}, bind=${HOST}:${PORT})"
  if [[ "${USE_GUNICORN}" == "1" ]]; then
    exec gunicorn -c "${SCRIPT_DIR}/gunicorn.conf.py" bradlyai.main:app
  else
    exec python run.py --host "${HOST}" --port "${PORT}"
  fi
fi

# ---- Background mode with crash-loop guard ----
# We use a supervisor bash loop: if the worker dies, restart it
# unless it's been killed too many times in RESTART_WINDOW_SEC.
start_supervised() {
  # Spawn a tiny supervisor that re-launches the worker on exit
  (
    trap '' HUP                              # ignore SIGHUP so disown works
    restarts=0
    while :; do
      log "▶ Launching worker (attempt $((restarts+1)))"
      if [[ "${USE_GUNICORN}" == "1" ]]; then
        gunicorn -c "${SCRIPT_DIR}/gunicorn.conf.py" \
                 --bind "${HOST}:${PORT}" \
                 bradlyai.main:app \
          >> "${LOG_FILE}" 2>&1
      else
        python run.py --host "${HOST}" --port "${PORT}" \
          >> "${LOG_FILE}" 2>&1
      fi
      WORKER_EXIT=$?
      log "⚠ Worker exited with code ${WORKER_EXIT}"
      restarts=$((restarts + 1))
      if [[ ${restarts} -ge ${MAX_RESTARTS} ]]; then
        log "❌ Max restarts (${MAX_RESTARTS}) reached in ${RESTART_WINDOW_SEC}s — giving up"
        exit 1
      fi
      log "↻ Restarting in 5s…"
      sleep 5
    done
  ) >> "${LOG_FILE}" 2>&1 &
  SUPERVISOR_PID=$!
  echo ${SUPERVISOR_PID} > "${PID_FILE}"
  # Give uvicorn/gunicorn a moment to bind the port
  sleep 3
  # Find the real worker PID (child of supervisor)
  WORKER_PID=$(pgrep -P "${SUPERVISOR_PID}" -f "uvicorn|gunicorn|run.py" | head -1 || echo "")
  if [[ -n "${WORKER_PID}" ]] && kill -0 "${WORKER_PID}" 2>/dev/null; then
    log "✅ BradlyAI worker running (supervisor PID ${SUPERVISOR_PID}, worker PID ${WORKER_PID})"
    return 0
  fi
  # If supervisor died, fail loudly
  if ! kill -0 "${SUPERVISOR_PID}" 2>/dev/null; then
    log "❌ Supervisor exited immediately. Last 30 log lines:"
    tail -30 "${LOG_FILE}" >&2 || true
    rm -f "${PID_FILE}"
    return 1
  fi
  log "✅ BradlyAI supervisor running (PID ${SUPERVISOR_PID})"
}

log "Starting BradlyAI in BACKGROUND (env=${ENVIRONMENT}, bind=${HOST}:${PORT}, db=${DATABASE_URL})"
log "PID file: ${PID_FILE}"
log "Log file: ${LOG_FILE}"
log "Engine: $([[ ${USE_GUNICORN} -eq 1 ]] && echo 'gunicorn' || echo 'uvicorn')"
log "Crash loop: up to ${MAX_RESTARTS} auto-restarts"

if ! start_supervised; then
  exit 1
fi
log "Dashboard:   http://${HOST}:${PORT}/"
log "Swagger UI:  http://${HOST}:${PORT}/docs"
log "Health:      http://${HOST}:${PORT}/health"
echo
echo "Stop with:    ./deploy/stop.sh"
echo "Status with:  ./deploy/status.sh"
echo "Tail logs:    tail -f ${LOG_FILE}"
