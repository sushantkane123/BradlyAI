# 🛡️ BradlyAI — Advanced Python Driverless SOC & Incident Response Platform

![BradlyAI Branding](https://img.shields.io/badge/BradlyAI%20Technology-AI%20Cyber%20Security-00f0ff?style=for-the-badge)
![Driverless Status](https://img.shields.io/badge/Driverless%20SOC-100%25%20Autonomous-10b981?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20SQLite-3b82f6?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.1.0--PRO-8b5cf6?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-11%2F11%20Passing-22c55e?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

Welcome to the definitive full-stack **Python (FastAPI)** repository and interactive enterprise dashboard for **BradlyAI**, Asia's leading AI-driven cybersecurity platform. Engineered for absolute agility, this project gives developers complete sovereign control over their Security Operations Center (SOC) with real OpenAI / Groq generative streaming, WebSockets, Web Audio feedback, and SQLite SIEM persistence.

---

## 🌟 What makes this Architecture Superior?

While commercial enterprise platforms are amazing at real-world multi-tenant threat hunting, they act as closed-source proprietary black boxes requiring heavy multi-year licensing.

**This repository gives you absolute open-architecture agility:**

1. **100% Extensible Python & Web:** Every single line of anomaly parsing, SQLite persistence, and UI logic is fully visible and documented.
2. **True Generative AI Integration:** Connect your real **OpenAI** or **Groq** API keys via `.env` or the in-app SOC Settings modal. v2.1 switches to fully **async HTTP** (`httpx`) for zero-blocking LLM calls.
3. **Continuous Background Telemetry Simulation:** An async worker (`LiveSimulationWorker`) generates realistic organic packet logs, persists them to SQLite, and broadcasts via WebSockets in real time.
4. **Standalone Web Audio Synthesizer:** Custom JavaScript `CyberAudio` class generates laser, shield, alarm, and radar sound feedback with **zero external sound files or CDNs**.
5. **Async-First Architecture (v2.1):** `aiosqlite` + `AsyncSession` for non-blocking DB operations, async LLM client, and structured logging throughout.
6. **Production-Ready Health Checks:** `GET /health` returns DB connectivity, worker status, and uptime — ready for load balancers and monitoring.

---

## 🚀 Key Interactive Dashboard Features

### 📊 1. Executive Dashboard & Live Cyber Radar
- **Enterprise Status Cards:** Digital Resilience Index, Autonomous Containment Rate (99.4%), Mean Time To Respond (MTTR), monitored SQLite endpoints.
- **Floating Diagnostic Node Hubs:** Hover or click on regional Pods in the Live Multi-Model Threat Map to inspect ping latencies, active EDR mesh agents, and CPU triage loads.
- **Activity Trends Canvas:** Spline charts showing real-time driverless interceptions vs. manual analyst workflows.

### ⚡ 2. Automated Incident Response (AIR) Live Pipeline
- **Autonomous Demo:** Select adversary scenarios (**APT29 Lateral Movement** vs **Zero-Day Supply Chain**) and click **Start Autonomous AIR Resolution** to watch FastAPI execute sub-second containment with typewriter-style streaming console logs.

### 🌐 3. Attack Surface Management (ASM)
- **Zero-Day Risk Inventory:** Monitor web services, S3 buckets, and Kubernetes clusters. Click **Autonomous AI Auto-Remediate** to instantly issue virtual firewall patches.

### 🔍 4. AI Threat Hunter & Memory Forensics
- **Live Memory Branches:** Dissect parent-child execution process trees highlighting reflective DLL injections.
- **Tactile Actions:** Execute **⚡ Kill PID**, **🛡️ Isolate Memory**, and **💾 Download Memory Dump** from the UI.

### ⚙️ 5. System Configuration & AI Connect Modal
- Open **SOC Settings** to paste your **OpenAI / Groq API Keys**, adjust auto-containment thresholds, toggle telemetry workers, or purge the SQLite database.

### 💬 6. Cyber-AI Security Copilot Chatbot
- Pre-baked quick prompt chips + custom queries via **FastAPI chunk-by-chunk streaming (`StreamingResponse`)**. Now powered by unified async LLM client with Groq (Llama-3) and OpenAI (GPT-4) support.

### 🆕 7. Real Log Ingestion & Detection Engine (v2.1)
- Upload real security logs via REST API (`/api/v1/ingest/logs/text`, `/upload`) and get instant rule-based detection with 6 built-in detection rules covering PowerShell attacks, SMB lateral movement, data exfiltration, IAM privilege escalation, process injection, and brute force.

---

## 📂 Repository Structure

```text
.
├── .env.example           # Self-documenting environment config template
├── .gitignore             # Excludes venvs, local SQLite DBs, preview caches
├── docker-compose.yml     # One-click deployment (docker-compose up -d --build)
├── Dockerfile             # Multi-stage optimized Python 3.11 Slim container
├── README.md              # Documentation & deployment guides
├── CHANGELOG.md           # Full version history v1.0.0 → v2.1.0
├── CONTRIBUTING.md        # Developer onboarding & contribution guide
├── LICENSE                # MIT License
├── requirements.txt       # Dependencies (fastapi, uvicorn, sqlalchemy, httpx, aiosqlite, etc.)
├── pytest.ini             # Pytest configuration
├── run.py                 # Local FastAPI development runner (python run.py)
├── bradlyai_cli.py        # Advanced Terminal CLI (python bradlyai_cli.py --alerts)
├── .github/workflows/
│   └── ci.yml             # GitHub Actions CI pipeline
├── sample_logs/           # Sample log files for ingestion testing
├── tests/
│   ├── __init__.py
│   └── test_api.py        # 11 integration tests — all passing ✅
└── bradlyai/              # Main Python package
    ├── __init__.py
    ├── main.py            # FastAPI entrypoint, lifespan, middleware, health check
    ├── config.py          # Pydantic Settings with .env support (14 config fields)
    ├── database.py        # SQLAlchemy sync + async engine & session management
    ├── models/            # ORM models (AlertModel, AssetModel, StorylineModel)
    ├── schemas/           # Pydantic request/response validation schemas
    ├── services/          # Business logic (AI engine, copilot, detection, log ingestion, AIR)
    ├── routers/           # Modular API routes (/api/v1/alerts, /chat, /ingest, /ws, etc.)
    └── static/            # Self-contained SPA (index.html, style.css, app.js, data.js)
```

---

## 🛠️ How to Pull & Deploy Locally

### Option A: Clone & Run via Docker

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
docker-compose up -d --build
```

### Option B: Native Python Development

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # Edit .env with your API keys
python run.py
```

Access the live dashboard at **`http://localhost:8000/`** and Swagger UI at **`http://localhost:8000/docs`**.

### Managing via Terminal CLI

```bash
python bradlyai_cli.py --status
python bradlyai_cli.py --alerts CRITICAL
python bradlyai_cli.py --trigger-attack 0
```

---

## 🔌 API Overview

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check — DB, worker, uptime |
| `/api/v1/alerts` | GET | List/search/paginate security alerts |
| `/api/v1/alerts/trigger-simulated-attack` | POST | Trigger a simulated cyber attack |
| `/api/v1/asm/assets` | GET | Attack Surface Management inventory |
| `/api/v1/asm/remediate/{id}` | POST | Auto-remediate an asset |
| `/api/v1/air/run-pipeline/{idx}` | POST | Execute AIR pipeline scenario |
| `/api/v1/forensics/process-tree/{host}` | GET | Memory process tree for a host |
| `/api/v1/mitre/matrix` | GET | MITRE ATT&CK coverage matrix |
| `/api/v1/chat` | POST | AI Copilot (streaming or non-streaming) |
| `/api/v1/ingest/logs/text` | POST | Ingest raw security logs |
| `/api/v1/ingest/logs/upload` | POST | Upload log file |
| `/api/v1/ws/stream` | WS | Real-time WebSocket telemetry stream |
| `/api/v1/system/config` | GET/POST | View/update system configuration |
| `/api/v1/system/reset-database` | POST | Purge and reseed the database |

Full interactive docs at **`http://localhost:8000/docs`** and **`http://localhost:8000/redoc`**.

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

```
tests/test_api.py::test_read_main           ✅ PASSED
tests/test_api.py::test_health_check        ✅ PASSED
tests/test_api.py::test_get_alerts          ✅ PASSED
tests/test_api.py::test_get_assets          ✅ PASSED
tests/test_api.py::test_trigger_attack      ✅ PASSED
tests/test_api.py::test_ingest_real_logs    ✅ PASSED
tests/test_api.py::test_chat_copilot        ✅ PASSED
tests/test_api.py::test_get_mitre_matrix    ✅ PASSED
tests/test_api.py::test_get_forensic_tree   ✅ PASSED
tests/test_api.py::test_system_config       ✅ PASSED
tests/test_api.py::test_system_reset        ✅ PASSED
```

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `groq` | AI provider: `groq` or `openai` |
| `GROQ_API_KEY` | — | Groq API key (free at [console.groq.com](https://console.groq.com)) |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `AUTO_CONTAINMENT_THRESHOLD` | `0.85` | AI confidence threshold for auto-containment |
| `LIVE_SIMULATION_WORKER_ACTIVE` | `true` | Enable background telemetry simulation |
| `SIMULATION_INTERVAL_SECONDS` | `30` | Seconds between simulated alerts |
| `RATE_LIMIT_ENABLED` | `true` | Enable API rate limiting |
| `ENVIRONMENT` | `development` | Deployment environment |

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, code style guide, and pull request process.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

### v2.1.0 Highlights (2026-06-19)

- 🔧 Fixed 6 critical bugs (missing methods, broken routes, rebrand residue, config gaps)
- ⚡ Async DB (`aiosqlite`) + async HTTP LLM client (`httpx`)
- 🩺 Health check endpoint (`GET /health`)
- 📝 Structured logging replacing all `print()` calls
- 🆕 `.env.example`, `LICENSE`, `CONTRIBUTING.md`, `CHANGELOG.md`
- 🧪 11/11 tests passing (up from 7/10)
