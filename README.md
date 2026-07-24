# BradlyAI — Autonomous SOC L1 Agent (Dropzone-style)

**BradlyAI is an autonomous, AI-powered Security Operations Center that investigates every alert without human intervention — just like Dropzone AI.**

It autonomously performs the full L1 triage workflow:

| OSCAR Phase | What Happens |
|---|---|
| **O**btain | Receives alerts from SIEM, XDR, EDR, and any security tool. Normalizes and extracts entities (IPs, hosts, users, hashes, domains). |
| **S**trategize | Formulates 3+ hypotheses about why each alert fired. Plans evidence collection prioritized by data source. |
| **C**ollect | Queries your security tools — EDR, Identity, Network, Threat Intel, SIEM — just like a human analyst would. |
| **A**nalyze | Recursively evaluates hypotheses against evidence. Deepens investigation until confidence exceeds threshold. |
| **R**eport | Composes a clear BENIGN / SUSPICIOUS / MALICIOUS disposition with confidence, reasoning, and raw evidence links. |

> **No human in the critical path.** Every alert gets a thorough, consistent investigation — 3 AM or 3 PM, same depth.

---

## BradlyAI vs Dropzone AI — Feature Comparison

| Feature | BradlyAI | Dropzone AI |
|---|---|---|
| **Autonomous L1 investigation** | ✅ No human needed | ✅ |
| **OSCAR methodology** | ✅ 5-phase recursive investigation | ✅ |
| **Recursive reasoning** | ✅ 3-level depth, re-evaluates until confident | ✅ |
| **Multi-hypothesis formulation** | ✅ 3+ per alert type | ✅ |
| **Pre-trained alert patterns** | ✅ Phishing, Malware, Brute Force, PrivEsc, Exfil, Scanner | ✅ |
| **EDR connectors** | ✅ CrowdStrike, Defender, SentinelOne, Carbon Black | ✅ |
| **Identity connectors** | ✅ Azure AD, Okta | ✅ |
| **Network containment** | ✅ Palo Alto, Fortinet, Cisco, Check Point | ✅ |
| **Threat intelligence** | ✅ VirusTotal, AbuseIPDB, OTX, MISP | ✅ |
| **Glass-box transparency** | ✅ Every step, query & decision auditable | ✅ |
| **SIEM integrations** | ✅ Splunk, Sentinel, Wazuh, Elastic, QRadar | ✅ |
| **ITSM integrations** | ✅ ServiceNow, Jira, Zendesk | ✅ |
| **Auto-investigate every alert** | ✅ Ingest → Investigate in one call | ✅ |
| **Natural language coaching** | ✅ Whitelist, rules, context in plain English | ✅ |
| **Connector-based (no log migration)** | ✅ Queries tools via API, no data movement | ✅ |
| **Context graph enrichment** | ✅ Single-shot pre-enrichment for LLM triage | ✅ |
| **Notifications** | ✅ Slack, Teams, PagerDuty, Email, Webhook | ✅ |
| **Sigma rules** | ✅ Import, evaluate, built-in library | ✅ |
| **Playbooks** | ✅ Declarative DAG with approval gating | ✅ |
| **RBAC + SSO** | ✅ JWT, MFA, OIDC, SAML, API keys | ✅ |
| **Open source** | ✅ MIT License | ❌ Proprietary |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Git
- Optional: Docker & Docker Compose, PostgreSQL

### Run locally

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
python run.py --reload
```

Open:

| URL | Description |
|---|---|
| `http://127.0.0.1:8000/` | Main SOC Dashboard |
| `http://127.0.0.1:8000/dropzone` | **Dropzone-style Autonomous Dashboard** |
| `http://127.0.0.1:8000/docs` | Interactive API Reference |
| `http://127.0.0.1:8000/api/v1/dropzone/dashboard` | Investigation Stats API |

### Run with Docker

```bash
cp .env.example .env
docker compose up --build
```

---

## Try Autonomous Investigation

### 1. Send an alert → auto-investigate (Dropzone-style)

```bash
curl -X POST http://127.0.0.1:8000/api/v1/dropzone/ingest-and-investigate \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "sentinel",
    "auto_investigate": true,
    "payload": {
      "SystemAlertId": "test-001",
      "AlertDisplayName": "Suspicious PowerShell encoded command detected",
      "Severity": "High",
      "CompromisedEntity": "LAB-WIN-01",
      "Entities": {"hostname": "LAB-WIN-01", "source_ip": "10.0.0.45"}
    }
  }'
```

### 2. Auto-investigate all pending alerts

```bash
curl -X POST http://127.0.0.1:8000/api/v1/dropzone/investigate/all?limit=50
```

### 3. View investigation results

```bash
curl http://127.0.0.1:8000/api/v1/dropzone/investigations?limit=10
curl http://127.0.0.1:8000/api/v1/dropzone/dashboard?since_hours=24
```

### 4. Investigate a specific alert

```bash
curl -X POST http://127.0.0.1:8000/api/v1/dropzone/investigate/ALT-8921
```

---

## Autonomous Investigation Flow

```
Security alert arrives from SIEM/XDR/EDR
     ↓
┌─────────────────────────────────────────┐
│  O — OBTAIN                              │
│  Normalize, extract entities, classify   │
├─────────────────────────────────────────┤
│  S — STRATEGIZE                          │
│  Formulate 3+ hypotheses, plan queries   │
├─────────────────────────────────────────┤
│  C — COLLECT                             │
│  Query EDR, Identity, Network, TI, SIEM  │
├─────────────────────────────────────────┤
│  A — ANALYZE (recursive)                 │
│  Evaluate evidence → confidence low?     │
│  → Deepen analysis → Evaluate again      │
├─────────────────────────────────────────┤
│  R — REPORT                              │
│  BENIGN / SUSPICIOUS / MALICIOUS         │
│  + confidence + reasoning + evidence     │
└─────────────────────────────────────────┘
     ↓
Auto-close (benign)  or  Escalate to L2 analyst
```

---

## Dropzone API Reference

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/v1/dropzone/ingest-and-investigate` | Ingest alert + auto-investigate (Dropzone-style) |
| `POST` | `/api/v1/dropzone/investigate/{alert_id}` | Full OSCAR investigation on existing alert |
| `POST` | `/api/v1/dropzone/investigate/all` | Auto-investigate all pending alerts |
| `GET` | `/api/v1/dropzone/investigations` | List all autonomous investigations |
| `GET` | `/api/v1/dropzone/investigations/{id}` | Full investigation detail with OSCAR steps |
| `GET` | `/api/v1/dropzone/dashboard` | Investigation stats, throughput, connectors |
| `POST` | `/api/v1/dropzone/webhook/alert` | Webhook for SIEM/SOAR tools to push alerts |

---

## Supported Alert Sources

| Source | Auto-Investigate | Notes |
|---|---|---|
| Wazuh | ✅ | Webhook + Manager API integration |
| Splunk | ✅ | REST API + webhook |
| Microsoft Sentinel | ✅ | Azure Monitor integration |
| Microsoft Defender for Endpoint | ✅ | Full EDR connector |
| CrowdStrike Falcon | ✅ | Full EDR connector |
| Elastic / ELK | ✅ | REST API |
| IBM QRadar | ✅ | REST API |
| Generic SIEM | ✅ | Webhook-based, any format |
| Generic XDR/EDR | ✅ | Webhook-based, any format |
| Custom webhooks | ✅ | `POST /api/v1/dropzone/webhook/alert` |

---

## Project Structure

```text
bradlyai/
├── routers/
│   ├── dropzone.py            # ⭐ Dropzone autonomous investigation API
│   ├── agent.py               # Evidence-first investigation agent
│   ├── l1_agent.py            # L1 decision engine API
│   ├── auth.py, cases.py ...  # RBAC, case management, etc.
├── services/
│   ├── dropzone_agent.py      # ⭐ OSCAR autonomous investigation engine
│   ├── investigation_agent.py # Evidence-first investigation
│   ├── l1_decision_engine.py  # 5-signal L1 decision engine
│   ├── context_graph.py       # 360° context enrichment
│   ├── edr/, identity/, network/, threatintel/  # Security tool connectors
├── models/                    # Database models
├── static/
│   ├── dropzone.html          # ⭐ Dropzone-style autonomous dashboard
│   ├── index.html             # Main SOC dashboard
├── tests/                     # 62+ tests
└── examples/real-data/        # Test alert payloads
```

---

## Security Notes

- All integrations default to **disabled + dry-run** — must be explicitly enabled
- Autonomous agent **never** performs containment without explicit configuration
- Start in shadow mode, review results, then enable active mode
- Change `AUTH_JWT_SECRET` and bootstrap admin password in production
- Use HTTPS, PostgreSQL, and a secret manager for production

---

## Contributing

```bash
git fork https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
pip install -r requirements.txt
pytest -q  # 62 tests passing
```

---

## License

MIT. See [LICENSE](LICENSE).
