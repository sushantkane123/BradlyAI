# BradlyAI

**BradlyAI helps security teams investigate alerts from SIEM, XDR, EDR, and custom security tools.**

It collects alert evidence, checks recent history, helps analysts create cases, and recommends what to do next:

```text
Escalate  → needs analyst attention
Review    → more evidence is needed
Auto-close candidate → may be safe only after customer policy and analyst approval
```

BradlyAI is built for security teams, MSSPs, contributors, and anyone learning how modern SOC automation works.

> BradlyAI starts in a safe mode. It does not automatically isolate devices, disable users, block IPs, or close high-risk alerts.

---

## What can BradlyAI do?

- Show security alerts in a SOC dashboard
- Accept alerts from multiple security tools
- Keep the original source event as evidence
- Help investigate alerts using a structured SOC workflow
- Create and track investigation cases
- Record notes, evidence, decisions, and audit history
- Work in **shadow mode** before any automated action is enabled
- Support Wazuh, Splunk, Microsoft Sentinel, Microsoft Defender, CrowdStrike, Elastic, generic SIEM, XDR, EDR, and custom webhooks

---

## How it works

```text
Security alert
     ↓
BradlyAI normalizes and stores the alert
     ↓
L1 decision checks rules, history, repeats, and policies
     ↓
Investigation agent collects available evidence and creates a plan
     ↓
Analyst reviews the recommendation
     ↓
Case, escalation, or approved policy action
```

---

## Quick start

### What you need

- Python 3.11 or newer
- Git
- Optional: Docker and Docker Compose
- PostgreSQL for production use
- SQLite is fine for local testing

### Run locally with Python

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI

python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env
python run.py --reload
```

Open these URLs:

```text
Dashboard:  http://127.0.0.1:8000/
API docs:   http://127.0.0.1:8000/docs
Health:     http://127.0.0.1:8000/health
```

### Run with Docker

```bash
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
cp .env.example .env

# Set unique local secrets before starting Docker.
# On Linux/macOS you can generate values with: openssl rand -hex 32
# Edit .env and set POSTGRES_PASSWORD, AUTH_JWT_SECRET, and BOOTSTRAP_ADMIN_PASSWORD.

docker compose up --build
```

---

## Try it with real-shaped test data

The included configuration starts with no fake dashboard alerts:

```dotenv
DEMO_DATA_ENABLED=false
LIVE_SIMULATION_WORKER_ACTIVE=false
INGESTION_DEFAULT_MODE=shadow
```

That means the dashboard will show only alerts you send to it.

### Send a safe Microsoft Sentinel test alert

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/sentinel-powershell.json
```

### Send a batch of SIEM, XDR, and EDR test alerts

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest/events/batch \
  -H 'Content-Type: application/json' \
  --data @examples/real-data/batch.json
```

Then refresh the dashboard or run:

```bash
curl http://127.0.0.1:8000/api/v1/alerts
```

More examples are in [`examples/real-data`](examples/real-data/README.md).

---

## Supported alert sources

| Source | Status |
|---|---|
| Wazuh | Supported |
| Splunk | Supported |
| Microsoft Sentinel | Supported |
| Microsoft Defender for Endpoint | Supported |
| CrowdStrike Falcon | Supported |
| Elastic / Elasticsearch | Supported |
| Generic SIEM | Supported |
| Generic XDR | Supported |
| Generic EDR | Supported |
| Custom webhooks | Supported |

A source event is sent in this format:

```json
{
  "source": "sentinel",
  "mode": "shadow",
  "payload": {
    "SystemAlertId": "example-001",
    "AlertDisplayName": "Suspicious PowerShell command",
    "Severity": "High",
    "CompromisedEntity": "LAB-WIN-01"
  }
}
```

Send it to:

```text
POST /api/v1/ingest/events
```

---

## Investigation agent

For each stored alert, an authenticated analyst can run an investigation.

The agent:

1. Reads the original alert evidence
2. Checks related alerts from the previous 24 hours
3. Checks asset and source information
4. Identifies missing evidence
5. Builds possible explanations
6. Recommends escalation, review, or an approved-policy candidate
7. Saves the investigation record for later review

API route:

```text
POST /api/v1/agent/alerts/{alert_id}/investigate
```

The agent does **not** make containment changes on its own.

Read more in [docs_SOC_INVESTIGATION_AGENT.md](docs_SOC_INVESTIGATION_AGENT.md).

---

## Cases

Analysts can create a case from an alert or create a case manually.

Each case can include:

- Priority and severity
- Assignee
- Status
- Linked alerts
- Notes
- Evidence such as IPs, hashes, URLs, domains, hosts, and logs
- SLA information

Open the **Cases** page in the dashboard after signing in.

---

## Wazuh quick test

BradlyAI can be tested with Wazuh without connecting to a real production manager:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/integration/wazuh/test-webhook \
  -H 'Content-Type: application/json' \
  -d '{
    "rule_level": 3,
    "rule_id": "1001",
    "rule_description": "Vulnerability scanner heartbeat",
    "agent_name": "LAB-SCANNER",
    "agent_ip": "10.0.0.50",
    "mitre_id": "T1595"
  }'
```

For a real Wazuh connection, start with:

```dotenv
WAZUH_ENABLED=true
WAZUH_DRY_RUN=true
WAZUH_CLOSE_MODE=comment_only
```

Do not enable archive or close actions until your team has reviewed the results in shadow mode.

---

## Important API routes

| Route | What it does |
|---|---|
| `GET /health` | Checks that the application is running |
| `GET /api/v1/alerts` | Lists alerts |
| `GET /api/v1/alerts/{id}` | Shows one alert and its evidence |
| `POST /api/v1/ingest/events` | Receives one real alert event |
| `POST /api/v1/ingest/events/batch` | Receives many alert events |
| `GET /api/v1/ingest/sources` | Lists accepted source types |
| `POST /api/v1/agent/alerts/{id}/investigate` | Runs an investigation |
| `GET/POST /api/v1/cases` | Lists or creates cases |
| `GET /api/v1/l1/audit` | Shows L1 decision history |
| `GET /api/v1/integration/wazuh/health` | Checks Wazuh integration status |

Use `/docs` for the full interactive API reference.

---

## Security notes

Before using BradlyAI with a real customer:

- Use HTTPS
- Use PostgreSQL, backups, and restricted database access
- Use a strong `AUTH_JWT_SECRET`
- Change the bootstrap admin password
- Use MFA and SSO when possible
- Store secrets in a secret manager, not in Git or chat
- Start in shadow mode
- Use IP allow-lists and webhook authentication
- Require human approval for containment actions

See [docs_REAL_DATA_MODE.md](docs_REAL_DATA_MODE.md) for safe ingestion guidance.

---

## Contributing

Contributions are welcome.

```bash
git fork https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
pip install -r requirements.txt
pytest -q
```

Before opening a pull request:

1. Keep changes focused.
2. Add or update tests.
3. Run `pytest -q`.
4. Do not add secrets, real client data, or production credentials.
5. Explain what changed and how it was tested.

Current test suite:

```text
63 tests passing
```

---

## Project structure

```text
bradlyai/
├── routers/       API routes
├── services/      SOC logic, decisions, investigations, integrations
├── models/        Database models
├── static/        Dashboard files
├── migrations.py  Database migration helper
examples/          Safe replay examples
tests/             Automated tests
docs_*.md          Feature guides
```

## License

MIT. See [LICENSE](LICENSE).
