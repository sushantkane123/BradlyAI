# Changelog

All notable changes to BradlyAI are documented in this file.

## [2.4.0] — Competitive Hardening

This release closes the competitive gap with established SOAR / autonomous
SOC platforms. Every feature below is production-ready and safe-by-default
(disabled or dry-run until explicitly enabled).

### Added — Authentication & RBAC
- JWT-based authentication (`/api/v1/auth/login`, refresh, /me)
- Built-in RBAC roles: `admin`, `analyst_l1`, `analyst_l2`, `responder`, `auditor`
- `require_permission(resource, action)` dependency for any router
- TOTP MFA with QR enrollment
- Account lockout (5 failures → 15-min lockout, configurable)
- API-key issuance with scopes (`X-API-Key`)
- OIDC SSO (Okta / Azure AD / Google / Auth0 / Keycloak) — generic, PKCE
- SAML SSO skeleton (IdP metadata + ACS) — install `python3-saml` to enable
- Bootstrap admin user (`admin` / `Admin123!ChangeMe`) on first boot — **CHANGE THIS**

### Added — Multi-Tenancy
- TenantModel with per-tenant scoping on alerts / cases / playbooks
- `MULTI_TENANCY_ENABLED=false` by default (single-tenant mode for backwards compat)
- Per-tenant RBAC and user assignment

### Added — Case Management
- Full case lifecycle: OPEN → IN_PROGRESS → ESCALATED → RESOLVED → CLOSED
- Notes, evidence (with chain-of-custody JSON), SLA tracking (P1=1h..P5=7d)
- Linked ITSM refs (ServiceNow sys_id, Jira key, Zendesk ticket id)
- `pending_approval_step` for human-gated playbook steps
- `POST /api/v1/cases/refresh-sla` to detect breaches

### Added — Playbook Engine
- Declarative JSON DAG executor with conditional routing (`on_true` / `on_false`)
- 3 built-in playbooks seeded on first boot:
  - `pb_phishing_response` — triage → enrich → isolate → ticket → notify
  - `pb_ransomware_response` — host + IP + user containment
  - `pb_bruteforce_response` — IP reputation decision tree
- 15+ action handlers: `edr_isolate_host`, `network_block_ip`,
  `identity_disable_user`, `notify_slack`, `create_jira_ticket`, etc.
- Approval-gated steps pause the run for human review (`AWAITING_APPROVAL`)
- Variable context propagation between steps via `$alert.ip`, `$case.id`, etc.

### Added — EDR Integrations (3 vendors)
- CrowdStrike Falcon — host contain, release, file hash quarantine
- Microsoft Defender for Endpoint — full isolate / unisolate / indicator block
- SentinelOne — disconnect / connect / threat classification
- VMware Carbon Black — quarantine / unquarantine / reputation override
- All safely default to `EDR_ENABLED=false`, `EDR_DRY_RUN=true`

### Added — Network Containment (4 vendors)
- Palo Alto (PAN-OS / Panorama XML API)
- Fortinet FortiGate REST API
- Cisco ASA REST API
- Check Point Management API
- Block / unblock IP + quarantine host

### Added — Identity Containment (2 vendors)
- Azure AD / Entra ID — disable / enable / revoke sessions / password reset
- Okta — lifecycle suspend / reactivate / session revoke / reset password

### Added — Notifications
- Slack (Bot Token, channel routing)
- Microsoft Teams (Incoming Webhook with adaptive cards)
- PagerDuty Events API v2 (severity-aware)
- Email (SMTP with TLS)
- Generic webhook
- `escalate_to_l2()` helper dispatches across all enabled channels
- Full notification audit log table

### Added — ITSM (3 vendors)
- ServiceNow Table API — create / update / list incidents
- Jira Cloud (two-way — extends existing Jira ingest)
- Zendesk Support — tickets / comments

### Added — Additional SIEMs
- Microsoft Sentinel (Azure Monitor)
- Elastic / ELK Stack
- IBM QRadar
- Splunk (REST API)

### Added — Threat Intel (4 vendors)
- VirusTotal v3 (IP / domain / file hash)
- AbuseIPDB
- AlienVault OTX
- MISP
- Unified `lookup_ip()` dispatcher across all sources

### Added — Sigma Rules
- SQLite-backed Sigma rule library
- YAML import via `/api/v1/sigma/import/file` or directory import
- Subset of Sigma DSL evaluator (selection / filter / 1 of / all of)
- 3 built-in rules seeded on first boot
- `POST /api/v1/sigma/evaluate` runs all enabled rules against an event

### Added — Observability
- Prometheus `/metrics` endpoint with custom counters / gauges / histograms:
  - `bradlyai_alerts_received_total{source}`
  - `bradlyai_alerts_closed_total{reason,decision}`
  - `bradlyai_llm_calls_total{provider,result}`
  - `bradlyai_playbook_runs_total{playbook_id,status}`
  - `bradlyai_decision_confidence` (histogram)
  - `bradlyai_open_cases{priority}` (gauge, refreshed per request)
  - `bradlyai_edr_actions_total`, `bradlyai_network_actions_total`, `bradlyai_identity_actions_total`
- `/health/live` and `/health/ready` liveness/readiness probes
- OpenTelemetry tracing auto-instrumentation (opt-in via `OTEL_ENABLED=true`)

### Added — Compliance & Operational Reporting
- `/api/v1/reports/kpis` — SOC KPI dashboard (MTTR, FP rate, override rate)
- `/api/v1/reports/audit.csv` — audit log CSV export
- `/api/v1/reports/nist-800-61` — NIST SP 800-61 r2 phase report
- `/api/v1/reports/soc2` — SOC 2 (CC6.1, CC7.2, CC7.3) evidence pack
- `/api/v1/reports/kpis.pdf` — PDF (reportlab) KPI report

### Changed
- Database engine now supports Postgres with connection pooling
- `bradlyai/models/__init__.py` registers all new models
- `bradlyai/migrations.py` handles all new columns / tables
- `bradlyai/main.py` registers all new routers under `/api/v1`
- `docker-compose.yml` adds a Postgres service + pgdata volume
- `.env.example` documents every new setting with safe defaults
- `requirements.txt` adds bcrypt, jose, pyotp, prometheus_client, reportlab, etc.

### Security Notes
- **CHANGE `AUTH_JWT_SECRET` in production** to a random 64+ char string
- **CHANGE the bootstrap admin password** after first login
- `*_DRY_RUN=true` defaults prevent accidental production actions
- `*_ENABLED=false` defaults keep all integrations inert until configured

## [2.3.0] — L1 SOC Agent + Wazuh Integration (previous)

- 5-signal decision engine (FP detector + duplicates + whitelist + LLM + history)
- Wazuh webhook ingest + Manager API auto-archive
- GreyNoise integration
- 27/27 pytest passing
