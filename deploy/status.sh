#!/usr/bin/env bash
# ============================================================================
# BradlyAI — Status / health check
# Shows process, port, memory, uptime, and live health endpoint.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/bradlyai.pid"
PORT="${PORT:-8000}"

# ---- Process ----
echo "=== Process ==="
if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
  PID=$(cat "${PID_FILE}")
  ps -p "${PID}" -o pid,etime,pcpu,pmem,rss,cmd --no-headers 2>/dev/null || echo "  (could not read ps)"
else
  echo "  not running"
fi

# ---- Port ----
echo
echo "=== Port ${PORT} ==="
ss -tlnp 2>/dev/null | grep ":${PORT}" || netstat -tlnp 2>/dev/null | grep ":${PORT}" || echo "  not listening"

# ---- Health endpoint ----
echo
echo "=== /health ==="
if command -v curl >/dev/null 2>&1; then
  RESP=$(curl -s -m 5 "http://127.0.0.1:${PORT}/health" 2>&1) && echo "${RESP}" | python3 -m json.tool 2>/dev/null || echo "${RESP}"
else
  echo "  curl not available"
fi

# ---- Disk ----
echo
echo "=== Persistent storage ==="
echo "  Database: $(ls -lh "${SCRIPT_DIR}/../data/bradlyai_soc.db" 2>/dev/null | awk '{print $5}') ($(ls -lh "${SCRIPT_DIR}/../data/bradlyai_soc.db" 2>/dev/null | awk '{print $9}'))"
echo "  Logs:     $(du -sh "${SCRIPT_DIR}/../logs" 2>/dev/null | awk '{print $1}')"

# ---- Recent log ----
echo
echo "=== Last 10 log lines ==="
LOG_FILE="${SCRIPT_DIR}/../logs/bradlyai.log"
if [[ -f "${LOG_FILE}" ]]; then
  tail -10 "${LOG_FILE}"
else
  echo "  no log file yet"
fi
