"""ITSM dispatch — ServiceNow, Jira (two-way), Zendesk."""
import logging
from typing import Any, Dict, Optional

from bradlyai.config import settings

logger = logging.getLogger("bradlyai.itsm")


def get_itsm_client():
    provider = (settings.ITSM_PROVIDER or "none").lower()
    if provider == "servicenow":
        from bradlyai.services.itsm.servicenow import ServiceNowClient
        return ServiceNowClient()
    if provider == "jira":
        from bradlyai.services.itsm.jira import JiraClient
        return JiraClient()
    if provider == "zendesk":
        from bradlyai.services.itsm.zendesk import ZendeskClient
        return ZendeskClient()
    return None
