# 🛡️ CyCraft AI - Advanced Python Driverless SOC & Incident Response Platform

![CyCraft Branding Flag](https://img.shields.io/badge/CyCraft%20Technology-AI%20Cyber%20Security-00f0ff?style=for-the-badge)
![Driverless Status](https://img.shields.io/badge/Driverless%20SOC-100%25%20Autonomous-10b981?style=for-the-badge)
![FastAPI Infrastructure](https://img.shields.io/badge/Backend-FastAPI%20%2B%20SQLite-3b82f6?style=for-the-badge)

Welcome to the definitive full-stack **Python (FastAPI)** repository and interactive enterprise dashboard for **CyCraft AI**, Asia’s leading AI-driven cybersecurity platform. Engineered for absolute agility, this project gives developers complete sovereign control over their Security Operations Center (SOC) with real Open AI / Groq generative streaming, WebSockets, Web Audio feedback, and SQLite SIEM persistence.

---

## 🌟 What makes this Architecture Superior?

While commercial enterprise platforms like CyCraft Technology are amazing at real-world multi-tenant threat hunting, they act as closed-source proprietary black boxes requiring heavy multi-year licensing. 

**This repository gives you absolute open-architecture agility:**
1. **100% Extensible Python & Web:** You have every single line of anomaly parsing, SQLite persistence, and UI logic fully visible and documented.
2. **True Generative Cloud Integration:** Connect your real **OpenAI or Groq API Keys** directly in the UI or `.env` to empower your Copilot with live LLM parsing and automated YARA rule compilation.
3. **Continuous Background Telemetry Simulation:** A multi-threaded asynchronous worker (`LiveSimulationWorker`) periodically generates realistic organic packet logs, commits them to SQLite, and broadcasts them out over WebSockets in real time.
4. **Standalone Web Audio Synthesizer:** Our custom JavaScript Web Audio synthesizer (`CyberAudio`) generates pristine laser, shield, alarm, and radar sound feedback with **zero external sound files or CDNs needed**.

---

## 🚀 Key Interactive Dashboard Features

### 📊 1. Executive Dashboard & Live Cyber Radar
- **Enterprise Status Cards:** Inspect your Digital Resilience Index, Autonomous Containment Rate (99.4%), Mean Time To Respond (MTTR), and monitored SQLite endpoints.
- **Floating Diagnostic Node Hubs:** Hover or click on regional Pods in your Live Multi-Model Threat Map to inspect live ping latencies, active EDR mesh agents, and CPU triage loads.
- **Activity Trends Canvas:** Spline charts showing real-time driverless interceptions compared to slow manual analyst workflows.

### ⚡ 2. Automated Incident Response (AIR) Live Pipeline
- **Autonomous Demo:** Select advanced adversary scenarios (**APT29 Lateral Movement** vs **Zero-Day Supply Chain**) and click **Start Autonomous AIR Resolution** to watch FastAPI execute sub-second containment and output typewriter-style streaming console logs.

### 🌐 3. Attack Surface Management (ASM)
- **Zero-Day Risk Inventory:** Monitor web services, S3 buckets, and Kubernetes clusters. Click **Autonomous AI Auto-Remediate** to instantly issue virtual firewall patches and update SQL risk scores to LOW.

### 🔍 4. AI Threat Hunter & Memory Forensics
- **Live Memory Branches:** Dissect parent-child execution process trees highlighting reflective DLL injections and command arguments.
- **Tactile Operational Actions:** Directly execute **⚡ Kill PID**, **🛡️ Isolate Memory**, and **💾 Download Memory Dump** from the UI.

### ⚙️ 5. System Configuration & Live AI Connect Modal
- Click **SOC Settings** at the top right to open an advanced interactive modal where you can paste your **OpenAI / Groq API Keys**, adjust your **Auto-Containment minimum threshold**, toggle background telemetry workers, or **Purge your SQLite Database**!

### 💬 6. Cyber-AI Security Copilot Chatbot
- Pre-baked with quick prompt chips or customized query handling via **FastAPI chunk-by-chunk generator streaming (`StreamingResponse`)**.

---

## 📂 Professional Repository Structure

```text
.
├── .gitignore             # Configured to exclude venvs, local SQLite DBs, and preview caches
├── docker-compose.yml     # Ready for one-click deployment (docker-compose up -d --build)
├── Dockerfile             # Multi-stage optimized Python 3.11 Slim container image
├── README.md              # Documentation & deployment guides
├── requirements.txt       # Essential Python dependencies (fastapi, uvicorn, sqlalchemy, pydantic, rich)
├── pytest.ini             # Pytest testing framework settings
├── run.py                 # Convenience local FastAPI development runner (python run.py)
├── cycraft_cli.py         # Advanced Terminal CLI tool (python cycraft_cli.py --alerts)
├── .github/workflows/
│   └── ci.yml             # Full Multi-Matrix GitHub Actions Continuous Integration pipeline
├── tests/
│   ├── __init__.py
│   └── test_api.py        # 9 automated integration tests covering all routes (100% passing)
└── cycraft/               # Main Python Python Package
    ├── __init__.py
    ├── main.py            # FastAPI Entrypoint, custom headers, and exception handlers
    ├── config.py          # Environment settings loaded via Pydantic Settings
    ├── database.py        # SQLAlchemy SQLite engine connection management
    ├── models/            # SQLAlchemy Database Models (Alerts & ASM Assets)
    ├── schemas/           # Pydantic Request Validation / Serialization Schemas
    ├── services/          # Business Logic (AI parsing, Copilot Generative streams, Background Workers)
    ├── routers/           # Fully Modular FastAPI API Routes (/api/v1/...)
    └── static/            # Self-contained Frontend SPA App (index.html, style.css, app.js)
```

---

## 🛠️ How to Pull & Deploy Locally

### Option A: Clone & Run via Docker
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
docker-compose up -d --build
```

### Option B: Native Python Development
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```
Access the Live Platform at `http://localhost:8000/` and Swagger UI Documentation at `http://localhost:8000/docs`.

### Managing via Terminal CLI
```bash
python cycraft_cli.py --status
python cycraft_cli.py --alerts CRITICAL
python cycraft_cli.py --trigger-attack 0
```
