# BradlyAI — Evidence-First SOC Operations

![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square)
![Tests](https://img.shields.io/badge/tests-62%20passing-16a34a?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-f5c518?style=flat-square)

**BradlyAI** is a policy-governed SOC operations platform for investigating security alerts from SIEM, XDR, EDR, and custom sources. It retains source evidence, correlates local history, creates analyst cases, and produces explainable recommendations—not unbounded autonomous containment.

> **Safety first:** Start every deployment in real-data **shadow mode**. BradlyAI records evidence and recommendations without external close, archive, containment, or account actions until a customer-approved policy explicitly permits them.

## How it works

```text
SIEM / XDR / EDR / custom event
              │
              ▼
Normalize + retain original source evidence
              │
              ▼
L1 decision signals + local correlation
              │
              ▼
Evidence-first SOC investigation agent
              │
              ▼
ESCALATE / REVIEW / AUTO_CLOSE_CANDIDATE
              │
              ▼
Analyst case workflow, approval, audit, and policy-gated response
```

## Core capabilities

| Capability | Description |
|---|---|
| **SOC dashboard** | Overview, alert queue, investigation drawer, integration health, and authenticated case workspace. |
| **Real-data mode** | Starts with no seeded showcase alerts and no simulation worker when configured for client/lab use. |
| **Multi-source ingestion** | Normalizes Wazuh, Splunk, Sentinel, Defender, CrowdStrike, Elastic, generic SIEM/XDR/EDR, and custom events. |
| **Raw evidence retention** | Preserves normalized source, signature, and original JSON payload for review. |
| **L1 decision engine** | Uses rule-based FP checks, recurrence, allow-lists, history, and optional LLM enrichment. |
| **SOC investigation agent** | Builds a structured plan, evidence, hypotheses, policy evaluation, and recommendation for analysts. |
| **Case management** | Creates cases from alerts, tracks ownership/status/SLA, and records notes and evidence. |
| **Wazuh controls** | Disabled-by-default integration, dry run, comment-only, and configurable close policy. |
| **Enterprise foundation** | JWT/API-key auth, RBAC, MFA support, SSO scaffolding, tenant model, audit logs, metrics, and reports. |

## Supported sources

```text
Wazuh                     Splunk
Microsoft Sentinel        Microsoft Defender for Endpoint
CrowdStrike Falcon        Elastic / Elasticsearch / ELK
Generic SIEM              Generic XDR
Generic EDR               Jira
Custom webhook payloads
```

Adapters normalize alert ID, severity, asset, IP, user, process, MITRE technique, timestamp, and source evidence. Direct vendor API polling/query collectors can be added per client after credentials, network access, and tenant policy are approved.

## Quick start

### Requirements

- Python 3.11+ (Python 3.13 is tested)
- Git
- Optional: Docker Engine and Docker Compose v2
- PostgreSQL for client/production deployments; SQLite is for local development only

### Local Python setup

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI

python -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

cp .env.example .env
python run.py --reload
```

Open:

```text
Dashboard:  http://127.0.0.1:8000/
API docs:   http://127.0.0.1:8000/docs
Health:     http://127.0.0.1:8000/health
```

### Docker

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
cp .env.example .env
docker compose up --build
```

For production, place BradlyAI behind TLS/reverse-proxy infrastructure and do not expose PostgreSQL publicly.

## Real-data local testing

The default `.env.example` is configured for a safe, empty workspace:

```dotenv
DEMO_DATA_ENABLED=false
LIVE_SIMULATION_WORKER_ACTIVE=false
INGESTION_DEFAULT_MODE=shadow
WAZUH_ENABLED=false
```

Only events you ingest or replay will appear in the dashboard. Replay a sanitized Sentinel event:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/sentinel-powershell.json
```

Replay generic SIEM, XDR, and EDR fixtures:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events/batch \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/batch.json
```

Inspect results:

```bash
curl http://127.0.0.1:8000/api/v1/alerts
curl 'http://127.0.0.1:8000/api/v1/l1/audit?since_hours=1'
```

Read [examples/real-data/README.md](examples/real-data/README.md) and [docs_REAL_DATA_MODE.md](docs_REAL_DATA_MODE.md) for the replay contract.

## Generic ingestion API

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/v1/ingest/sources` | Supported adapters and safety mode |
| `POST` | `/api/v1/ingest/events` | Persist and triage one real source event |
| `POST` | `/api/v1/ingest/events/batch` | Bounded batch/replay ingestion |

Single-event envelope:

```json
{
  "source": "sentinel",
  "mode": "shadow",
  "payload": {
    "SystemAlertId": "sentinel-lab-001",
    "AlertDisplayName": "Suspicious PowerShell command line",
    "Severity": "High",
    "CompromisedEntity": "LAB-WIN-01"
  }
}
```

Set `INGESTION_SHARED_SECRET` to require this header:

```http
X-Ingestion-Key: your-shared-secret
```

This is an additional application control, not a replacement for TLS, IP allow-lists, replay protection, rate limits, and preferably mTLS or an API gateway.

## Evidence-first SOC investigation agent

For an authenticated analyst with `alerts:read` permission:

```text
POST /api/v1/agent/alerts/{alert_id}/investigate
GET  /api/v1/agent/alerts/{alert_id}/investigations
GET  /api/v1/agent/investigations/{investigation_id}
```

The agent:

1. Validates source evidence.
2. Correlates matching alerts and asset activity from the previous 24 hours.
3. Records observed evidence separately from missing connector evidence.
4. Builds hypotheses and next steps.
5. Recommends `ESCALATE`, `REVIEW`, or `AUTO_CLOSE_CANDIDATE` under safety policy.
6. Saves the plan, evidence, hypotheses, policy result, and timestamps in a persistent investigation record.

The agent **does not** directly isolate endpoints, disable users, block IPs, archive alerts, or automatically close high-risk incidents. See [docs_SOC_INVESTIGATION_AGENT.md](docs_SOC_INVESTIGATION_AGENT.md).

## Case management

The authenticated Cases workspace supports:

- Manual or alert-linked case creation
- Priority, severity, assignee, status, and SLA tracking
- Investigation notes
- Evidence: IP, hash, domain, URL, host, log, and other artifacts
- Linked alerts
- Resolution and closure workflow

## Wazuh integration

Start with dry-run, comment-only safety settings:

```dotenv
WAZUH_ENABLED=true
WAZUH_DRY_RUN=true
WAZUH_CLOSE_MODE=comment_only
WAZUH_MANAGER_URL=https://wazuh.example.internal:55000
WAZUH_USER=bradlyai_service_account
WAZUH_PASSWORD=use-a-secret-manager
WAZUH_VERIFY_SSL=true
```

Test without contacting a production manager:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/integration/wazuh/test-webhook \
  -H 'Content-Type: application/json' \
  -d '{"rule_level":3,"rule_id":"1001","rule_description":"Vulnerability scanner heartbeat","agent_name":"LAB-SCANNER","agent_ip":"10.0.0.50","mitre_id":"T1595"}'
```

Do not enable archive/close actions until shadow results, customer policy, credentials, and action scope are reviewed.

## Key API routes

| Route | Purpose |
|---|---|
| `GET /health` | Application and database health |
| `GET /api/v1/alerts` | Alert queue |
| `GET /api/v1/alerts/{id}` | Alert detail and raw evidence |
| `GET/POST /api/v1/l1/mode` | View/set L1 active or shadow mode |
| `GET /api/v1/l1/audit` | L1 decision audit history |
| `GET/POST /api/v1/cases` | Case queue and creation |
| `POST /api/v1/integration/wazuh/test-webhook` | Safe Wazuh test |
| `GET /api/v1/integration/wazuh/health` | Wazuh integration health |

Full interactive documentation: `/docs`.

## Security and client deployment checklist

Before onboarding a client:

- Use PostgreSQL, encrypted backups, and restricted database access.
- Deploy behind TLS, WAF/reverse proxy, and network allow-lists.
- Set a strong `AUTH_JWT_SECRET`; never use the development default in production.
- Change the bootstrap admin password immediately.
- Enable MFA and configure SSO/OIDC or SAML where required.
- Use a client-specific tenant, connector credential, policy set, and ingestion key.
- Keep all ingestion and response actions in shadow/dry-run mode first.
- Require approval for containment, disable-user, block-IP, or destructive actions.
- Store secrets in a secret manager, never in source control or chat.

## Testing

```bash
pytest -q
```

The current suite contains **62 tests**, including API, auth/RBAC, L1 decision, real event ingestion, and investigation-agent coverage.

## Repository layout

```text
bradlyai/
├── routers/              # APIs: alerts, ingest, cases, agent, integrations
├── services/             # L1 decisioning, evidence investigation, connectors
├── models/               # Alerts, investigations, cases, tenants, audit records
├── static/               # SOC dashboard
├── migrations.py         # Lightweight schema migration helper
examples/real-data/       # Sanitized SIEM/XDR/EDR replay fixtures
docs_REAL_DATA_MODE.md
docs_SOC_INVESTIGATION_AGENT.md
```

## License

MIT. See [LICENSE](LICENSE).
