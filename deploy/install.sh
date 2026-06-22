#!/usr/bin/env bash
# ============================================================================
# BradlyAI — One-shot installer (production)
# - Creates venv
# - Installs dependencies
# - Generates a production .env
# - Verifies the install
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

echo "▶ Installing BradlyAI production dependencies into venv/"

# ---- Python check ----
PYTHON="${PYTHON:-python3}"
if ! command -v "${PYTHON}" >/dev/null 2>&1; then
  echo "❌ python3 not found. Install Python 3.10+ first." >&2
  exit 1
fi
PY_VER=$("${PYTHON}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  Python ${PY_VER}"

# ---- Create venv ----
if [[ ! -d "venv" ]]; then
  "${PYTHON}" -m venv venv
  echo "  venv created"
else
  echo "  venv exists (reusing)"
fi

# shellcheck disable=SC1091
source venv/bin/activate
pip install --quiet --upgrade pip wheel

# ---- Install runtime deps ----
echo "▶ Installing requirements"
pip install --quiet -r requirements.txt

# ---- Install gunicorn for production (optional but recommended) ----
if ! python -c "import gunicorn" >/dev/null 2>&1; then
  echo "▶ Installing gunicorn (production WSGI server)"
  pip install --quiet "gunicorn[standard]>=21.2"
fi

# ---- Generate production .env ----
if [[ ! -f ".env" ]]; then
  echo "▶ Generating .env from template"
  cp .env.example .env
  # Flip environment to production
  sed -i 's/^ENVIRONMENT=.*/ENVIRONMENT=production/' .env
fi

# ---- Create runtime dirs ----
mkdir -p data logs

# ---- Make scripts executable ----
chmod +x deploy/*.sh

# ---- Verify ----
echo "▶ Verifying install"
python -c "from bradlyai.config import settings; print(f'  ✅ App: {settings.APP_NAME}'); print(f'  ✅ Version: {settings.APP_VERSION}'); print(f'  ✅ Env: {settings.ENVIRONMENT}'); print(f'  ✅ DB: {settings.DATABASE_URL}')"

echo
echo "✅ Install complete!"
echo
echo "Next steps:"
echo "  1. (optional) edit .env to add GROQ_API_KEY or OPENAI_API_KEY"
echo "  2. start:   ./deploy/start.sh"
echo "  3. status:  ./deploy/status.sh"
echo "  4. stop:    ./deploy/stop.sh"
