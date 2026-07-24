# Changelog

All notable changes to BradlyAI will be documented in this file.

## [2.1.0] — 2026-06-19

### 🔧 Fixed
- **Missing `analyze_anomaly()` method** in `ai_engine.py` — Live Simulation Worker no longer crashes
- **Chat route: `GET` → `POST`** — Now matches test expectations and REST best practices
- **Missing config keys** — `ENVIRONMENT`, `AUTO_CONTAINMENT_THRESHOLD` added to `config.py`
- **App name mismatch** — Config now reads `"BradlyAI - Driverless SOC & Automated Incident Response"`
- **`requirements.txt` escaping** — Fixed `uvicorn\[standard\]` → `uvicorn[standard]`
- **`datetime.utcnow()` deprecation** — Replaced with `datetime.now(timezone.utc)` across 4 files

### ✨ Added
- **Async DB support** — `AsyncSession`/`aiosqlite` for non-blocking route handlers
- **Async HTTP in LLM client** — `httpx.AsyncClient` replaces blocking `requests.post()`
- **Health check endpoint** — `GET /health` returns DB connectivity, worker status, uptime
- **Rate limiting support** — `slowapi` ready for production deployment
- **`.env.example`** — Self-documenting environment config template
- **`LICENSE`** — MIT license
- **`CONTRIBUTING.md`** — Developer onboarding guide
- **`CHANGELOG.md`** — This file

### 🔄 Changed
- **Logging** — Replaced all `print()` calls with structured `logging` module
- **WebSocket manager** — Cleaner heartbeat, proper disconnect cleanup, no duplicate random tickers
- **Copilot services** — Unified LLM calls through `llm_client`, removed duplicate API logic
- **Detection engine** — Proper UTC timestamps instead of `"Just now"` strings
- **System config** — Returns `alerts_removed` count on DB reset
- **Config** — Migrated to `SettingsConfigDict` (Pydantic V2 style)

## [2.0.0] — 2026-06-18
- Groq/Llama-3 support in LLM client
- Real log ingestion (Phase 1) with detection engine
- Enhanced copilot for real-data analysis

## [1.0.0] — 2026-06-17
- Initial commit — workplace code
- FastAPI backend with SQLite persistence
- Dashboard SPA with Web Audio synthesizer
- AI Copilot, AIR pipeline, MITRE matrix, forensics
- 9 integration tests
