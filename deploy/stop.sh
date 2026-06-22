#!/usr/bin/env bash
# ============================================================================
# BradlyAI — Graceful shutdown
# Sends SIGTERM, waits up to 15s, escalates to SIGKILL if needed.
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/bradlyai.pid"

if [[ ! -f "${PID_FILE}" ]]; then
  echo "BradlyAI is not running (no PID file at ${PID_FILE})."
  exit 0
fi

PID=$(cat "${PID_FILE}")
if ! kill -0 "${PID}" 2>/dev/null; then
  echo "Stale PID file (process ${PID} not running). Cleaning up."
  rm -f "${PID_FILE}"
  exit 0
fi

echo "Sending SIGTERM to PID ${PID}…"
kill -TERM "${PID}"

# Wait up to 15 seconds for graceful shutdown
for i in {1..15}; do
  if ! kill -0 "${PID}" 2>/dev/null; then
    echo "✅ Stopped gracefully."
    rm -f "${PID_FILE}"
    exit 0
  fi
  sleep 1
done

echo "Graceful shutdown timed out — sending SIGKILL."
kill -9 "${PID}" 2>/dev/null || true
rm -f "${PID_FILE}"
echo "✅ Stopped (forced)."
