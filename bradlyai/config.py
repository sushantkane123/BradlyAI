"""
BradlyAI Configuration — Environment settings loaded via Pydantic Settings.

All new integration toggles default to SAFE / DISABLED so the application
remains production-safe out of the box. Integrations must be explicitly
enabled by setting the relevant _ENABLED flag and supplying credentials.
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Application Identity ──────────────────────────────────────────
    APP_NAME: str = "BradlyAI - Driverless SOC & Automated Incident Response"
    APP_VERSION: str = "2.4.0"
    ENVIRONMENT: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ── Database ───────────────────────────────────────────────────────
    # Default: SQLite. For production, use Postgres:
    #   DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/bradlyai
    DATABASE_URL: str = "sqlite+aiosqlite:///./bradlyai_soc.db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE: int = 1800

    # ── AI / LLM Configuration ────────────────────────────────────────
    LLM_PROVIDER: str = "groq"             # groq | openai | local
    GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY", "")
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", "")
    DEFAULT_AI_MODEL: str = "gpt-4-turbo-preview"
    LOCAL_LLM_MODEL_PATH: Optional[str] = None
    LOCAL_LLM_CONTEXT_SIZE: int = 4096

    # ── Autonomous SOC Settings ────────────────────────────────────────
    AUTO_CONTAINMENT_THRESHOLD: float = 0.85
    LIVE_SIMULATION_WORKER_ACTIVE: bool = True
    SIMULATION_INTERVAL_SECONDS: int = 30

    # ── Rate Limiting ──────────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 300
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # ── CORS ───────────────────────────────────────────────────────────
    CORS_ALLOWED_ORIGINS: List[str] = ["*"]

    # ── Wazuh Manager API Integration ───────────────────────────────────
    WAZUH_ENABLED: bool = False
    WAZUH_DRY_RUN: bool = True
    WAZUH_CLOSE_MODE: str = "comment_only"
    WAZUH_MANAGER_URL: str = ""
    WAZUH_USER: str = ""
    WAZUH_PASSWORD: str = ""
    WAZUH_VERIFY_SSL: bool = True

    # ══════════════════════════════════════════════════════════════════
    # ── Authentication / Authorization / SSO (NEW) ─────────────────────
    # ══════════════════════════════════════════════════════════════════
    AUTH_ENABLED: bool = True
    AUTH_JWT_SECRET: str = os.getenv("AUTH_JWT_SECRET", "CHANGE-ME-IN-PROD-" + os.urandom(8).hex())
    AUTH_JWT_ALGORITHM: str = "HS256"
    AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    AUTH_REQUIRE_MFA_FOR_ADMINS: bool = True
    AUTH_PASSWORD_MIN_LENGTH: int = 12
    AUTH_MAX_FAILED_LOGINS: int = 5
    AUTH_LOCKOUT_MINUTES: int = 15

    # SSO — OIDC (Okta, Azure AD, Google Workspace, Auth0, Keycloak)
    SSO_OIDC_ENABLED: bool = False
    SSO_OIDC_ISSUER: str = ""
    SSO_OIDC_CLIENT_ID: str = ""
    SSO_OIDC_CLIENT_SECRET: str = ""
    SSO_OIDC_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/sso/oidc/callback"
    SSO_OIDC_SCOPES: str = "openid email profile groups"

    # SSO — SAML (enterprise IdPs)
    SSO_SAML_ENABLED: bool = False
    SSO_SAML_ENTITY_ID: str = "bradlyai"
    SSO_SAML_IDP_METADATA_URL: str = ""
    SSO_SAML_SP_CERT_PATH: str = ""
    SSO_SAML_SP_KEY_PATH: str = ""

    # RBAC defaults
    RBAC_DEFAULT_ROLE: str = "analyst_l1"
    RBAC_ADMIN_ROLE: str = "admin"

    # ══════════════════════════════════════════════════════════════════
    # ── Multi-Tenancy (NEW) ────────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    MULTI_TENANCY_ENABLED: bool = False        # opt-in (single-tenant default)
    DEFAULT_TENANT_ID: str = "default"
    DEFAULT_TENANT_NAME: str = "Default Tenant"

    # ══════════════════════════════════════════════════════════════════
    # ── Notifications — Slack / Teams / PagerDuty / Email (NEW) ────────
    # ══════════════════════════════════════════════════════════════════
    NOTIFICATIONS_ENABLED: bool = False

    # Slack
    SLACK_ENABLED: bool = False
    SLACK_BOT_TOKEN: str = ""                 # xoxb-...
    SLACK_DEFAULT_CHANNEL: str = "#soc-alerts"
    SLACK_L2_CHANNEL: str = "#soc-l2"

    # Microsoft Teams (Incoming Webhook)
    TEAMS_ENABLED: bool = False
    TEAMS_WEBHOOK_URL: str = ""

    # PagerDuty
    PAGERDUTY_ENABLED: bool = False
    PAGERDUTY_INTEGRATION_KEY: str = ""       # Events API v2 routing key
    PAGERDUTY_DEFAULT_SERVICE_KEY: str = ""

    # Email (SMTP)
    EMAIL_ENABLED: bool = False
    EMAIL_SMTP_HOST: str = ""
    EMAIL_SMTP_PORT: int = 587
    EMAIL_SMTP_USE_TLS: bool = True
    EMAIL_SMTP_USERNAME: str = ""
    EMAIL_SMTP_PASSWORD: str = ""
    EMAIL_FROM_ADDRESS: str = "soc@bradlyai.local"
    EMAIL_L2_DISTRIBUTION_LIST: str = ""

    # Generic webhook (custom integrations)
    WEBHOOK_NOTIFY_ENABLED: bool = False
    WEBHOOK_NOTIFY_URL: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── EDR Integrations (NEW) ─────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    EDR_ENABLED: bool = False
    EDR_DRY_RUN: bool = True                  # SAFEST default
    EDR_PROVIDER: str = "none"                # none | crowdstrike | defender | sentinelone | carbonblack

    # CrowdStrike Falcon
    CROWDSTRIKE_CLIENT_ID: str = ""
    CROWDSTRIKE_CLIENT_SECRET: str = ""
    CROWDSTRIKE_BASE_URL: str = "https://api.crowdstrike.com"

    # Microsoft Defender for Endpoint
    DEFENDER_TENANT_ID: str = ""
    DEFENDER_CLIENT_ID: str = ""
    DEFENDER_CLIENT_SECRET: str = ""

    # SentinelOne
    SENTINELONE_API_TOKEN: str = ""
    SENTINELONE_BASE_URL: str = ""

    # VMware Carbon Black
    CARBONBLACK_API_ID: str = ""
    CARBONBLACK_API_SECRET: str = ""
    CARBONBLACK_BASE_URL: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── Network Containment — Firewall / NAC (NEW) ─────────────────────
    # ══════════════════════════════════════════════════════════════════
    NETWORK_ENABLED: bool = False
    NETWORK_DRY_RUN: bool = True
    NETWORK_PROVIDER: str = "none"            # none | paloalto | fortinet | cisco_asa | checkpoint

    PALOALTO_BASE_URL: str = ""
    PALOALTO_API_KEY: str = ""
    PALOALTO_VSYS: str = "vsys1"

    FORTINET_BASE_URL: str = ""
    FORTINET_API_TOKEN: str = ""

    CISCO_ASA_BASE_URL: str = ""
    CISCO_ASA_USERNAME: str = ""
    CISCO_ASA_PASSWORD: str = ""

    CHECKPOINT_BASE_URL: str = ""
    CHECKPOINT_USERNAME: str = ""
    CHECKPOINT_PASSWORD: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── Identity Containment — IAM (NEW) ───────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    IDENTITY_ENABLED: bool = False
    IDENTITY_DRY_RUN: bool = True
    IDENTITY_PROVIDER: str = "none"           # none | azure_ad | okta

    # Azure AD / Entra ID
    AZURE_AD_TENANT_ID: str = ""
    AZURE_AD_CLIENT_ID: str = ""
    AZURE_AD_CLIENT_SECRET: str = ""

    # Okta
    OKTA_DOMAIN: str = ""                     # e.g. dev-12345.okta.com
    OKTA_API_TOKEN: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── ITSM — ServiceNow / Zendesk (NEW) ──────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    ITSM_ENABLED: bool = False
    ITSM_PROVIDER: str = "none"               # none | servicenow | zendesk | jira
    SERVICENOW_INSTANCE_URL: str = ""
    SERVICENOW_USERNAME: str = ""
    SERVICENOW_PASSWORD: str = ""
    SERVICENOW_DEFAULT_ASSIGNMENT_GROUP: str = "SOC L2"
    SERVICENOW_IMPACT: str = "2"
    SERVICENOW_URGENCY: str = "2"

    # Jira (two-way — extends existing Jira ingest)
    JIRA_URL: str = ""
    JIRA_USERNAME: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_DEFAULT_PROJECT_KEY: str = "SEC"

    # Zendesk
    ZENDESK_SUBDOMAIN: str = ""
    ZENDESK_EMAIL: str = ""
    ZENDESK_API_TOKEN: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── Additional SIEMs (NEW) ─────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    SIEM_SPLUNK_ENABLED: bool = False
    SIEM_SPLUNK_HOST: str = ""
    SIEM_SPLUNK_PORT: int = 8089
    SIEM_SPLUNK_TOKEN: str = ""

    SIEM_ELASTIC_ENABLED: bool = False
    SIEM_ELASTIC_URL: str = ""
    SIEM_ELASTIC_USERNAME: str = ""
    SIEM_ELASTIC_PASSWORD: str = ""
    SIEM_ELASTIC_API_KEY: str = ""

    SIEM_QRADAR_ENABLED: bool = False
    SIEM_QRADAR_HOST: str = ""
    SIEM_QRADAR_TOKEN: str = ""

    SIEM_SENTINEL_ENABLED: bool = False
    SIEM_SENTINEL_TENANT_ID: str = ""
    SIEM_SENTINEL_CLIENT_ID: str = ""
    SIEM_SENTINEL_CLIENT_SECRET: str = ""
    SIEM_SENTINEL_SUBSCRIPTION_ID: str = ""
    SIEM_SENTINEL_RESOURCE_GROUP: str = ""
    SIEM_SENTINEL_WORKSPACE_NAME: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── Threat Intel (NEW) ─────────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    THREATINTEL_ENABLED: bool = False
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    MISP_URL: str = ""
    MISP_API_KEY: str = ""

    # ══════════════════════════════════════════════════════════════════
    # ── Playbook Engine (NEW) ──────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    PLAYBOOKS_ENABLED: bool = True
    PLAYBOOKS_DIR: str = "./playbooks"
    PLAYBOOKS_DEFAULT_TIMEOUT_SECONDS: int = 600
    PLAYBOOKS_MAX_STEPS: int = 50
    PLAYBOOKS_REQUIRE_APPROVAL_FOR: str = "isolate_host,disable_user,delete_data"

    # ══════════════════════════════════════════════════════════════════
    # ── Sigma Rule Engine (NEW) ────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    SIGMA_ENABLED: bool = True
    SIGMA_RULES_DIR: str = "./sigma_rules"
    SIGMA_AUTO_UPDATE: bool = False
    SIGMA_REPO_URL: str = "https://github.com/SigmaHQ/sigma.git"

    # ══════════════════════════════════════════════════════════════════
    # ── Compliance Reporting (NEW) ─────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    COMPLIANCE_FRAMEWORKS: str = "nist_800_61,soc2,iso_27001"
    COMPLIANCE_REPORT_DIR: str = "./reports"

    # ══════════════════════════════════════════════════════════════════
    # ── Observability (NEW) ────────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════
    METRICS_ENABLED: bool = True
    METRICS_PATH: str = "/metrics"
    OTEL_ENABLED: bool = False
    OTEL_EXPORTER_OTLP_ENDPOINT: str = ""
    OTEL_SERVICE_NAME: str = "bradlyai"


settings = Settings()
