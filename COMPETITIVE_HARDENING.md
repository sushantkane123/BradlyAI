# 🛡️ BradlyAI v2.4.0 — Competitive Hardening Summary

This release closes the competitive gap with established SOAR / autonomous
SOC platforms (Tines, Torq, Cortex XSOAR, Splunk SOAR, Swimlane, Radiant
Security, Dropzone AI, etc.).

> **Jump straight to the [CHANGELOG.md](CHANGELOG.md) for the full diff list.**

## What's new in 2.4.0 (one-line per feature)

| Area | Feature |
|---|---|
| 🔐 Auth | JWT login + refresh + MFA + RBAC + API keys + OIDC SSO + SAML SSO |
| 🏢 Tenancy | Multi-tenant scoping (opt-in) |
| 📋 Cases | Full case lifecycle + SLA + notes + evidence (chain-of-custody) |
| 🎬 Playbooks | Declarative DAG engine + 3 built-in + approval gating + 15+ actions |
| 🛡️ EDR | CrowdStrike, Defender, SentinelOne, Carbon Black |
| 🌐 Network | Palo Alto, Fortinet, Cisco ASA, Check Point |
| 👤 Identity | Azure AD, Okta (disable/enable/session revoke/password reset) |
| 🔔 Notifications | Slack, Teams, PagerDuty, Email, Webhook + audit log |
| 🎫 ITSM | ServiceNow, Jira (two-way), Zendesk |
| 📡 SIEMs | Splunk, Sentinel, Elastic, QRadar |
| 🕵️ Threat Intel | VirusTotal, AbuseIPDB, OTX, MISP |
| 📐 Sigma | Import / evaluate / 3 built-in rules |
| 📊 Observability | Prometheus /metrics + OTel + liveness/readiness |
| 📈 Reports | KPIs + NIST 800-61 + SOC 2 + audit CSV + PDF |

## How to apply this patch

```bash
# Clone the repo, then apply the patch
git clone https://github.com/sushantkane123/BradlyAI.git
cd BradlyAI
git checkout -b feature/competitive-hardening
git apply /path/to/bradlyai-competitive-hardening.patch
pip install -r requirements.txt
cp .env.example .env
# Edit .env — at minimum set AUTH_JWT_SECRET to a random string
python run.py
```

## Quickstart after applying

```bash
# 1. Login with bootstrap admin
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!ChangeMe"}'

# 2. Visit /metrics (Prometheus)
curl http://localhost:8000/metrics

# 3. Trigger a built-in playbook (dry-run by default)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin123!ChangeMe"}' | jq -r .access_token)

curl -X POST http://localhost:8000/api/v1/playbooks/trigger \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"playbook_id":"pb_bruteforce_response","alert":{"id":"ALT-1","ip":"1.2.3.4","severity":"HIGH"}}'

# 4. SOC KPIs
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/reports/kpis?since_hours=24"

# 5. NIST 800-61 incident-handling report
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/reports/nist-800-61?since_hours=168"
```

## Safety guarantees preserved

Every new integration has **two safety guards**:
- `*_ENABLED=false` (must explicitly enable)
- `*_DRY_RUN=true` (logs what would happen, never does it)

To enable any real action you must explicitly override **both** flags AND
supply credentials. This is documented in the new `.env.example`.

## Test coverage

```bash
pip install pytest httpx
pytest tests/test_competitive_hardening.py -v
```

40+ new tests cover:
- Auth (login, refresh, RBAC, MFA setup, API keys)
- Cases (CRUD, notes, evidence, status, SLA)
- Playbooks (trigger, resume, builtin library)
- Sigma (import, evaluate, 3 built-in rules)
- Notifications (5 channels, dry-run)
- EDR / Network / Identity (4-3-2 vendors, dry-run stubs)
- Reports (KPIs, NIST, SOC2, audit CSV)
- Metrics endpoint
- Threat intel (multi-source dry-run)
- ITSM (dry-run stub)

## Migration from v2.3.0 → v2.4.0

The migration is **additive**:
- New tables auto-created on first boot (`create_all`)
- Existing tables get new columns via `ALTER TABLE` (handled by `migrations.py`)
- Default users / roles / playbooks / Sigma rules are idempotently seeded
- No breaking changes to existing endpoints
