"""ITSM router — ServiceNow / Jira / Zendesk CRUD."""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bradlyai.database import get_db
from bradlyai.models.user import UserModel
from bradlyai.services.auth import require_permission
from bradlyai.services.itsm import get_itsm_client

router = APIRouter(prefix="/itsm", tags=["ITSM"])


class ServiceNowIncidentRequest(BaseModel):
    short_description: str
    description: str = ""
    urgency: Optional[str] = None
    impact: Optional[str] = None
    assignment_group: Optional[str] = None


class ServiceNowUpdateRequest(BaseModel):
    sys_id: str
    work_notes: Optional[str] = None
    state: Optional[str] = None


class JiraIssueRequest(BaseModel):
    project: Optional[str] = None
    summary: str
    description: str = ""
    issue_type: str = "Task"


class JiraCommentRequest(BaseModel):
    key: str
    comment: str


class ZendeskTicketRequest(BaseModel):
    subject: str
    comment: str
    priority: str = "normal"
    requester_email: Optional[str] = None


def _client():
    c = get_itsm_client()
    if c is None:
        raise HTTPException(status_code=503,
                            detail="ITSM provider not configured (ITSM_PROVIDER=none)")
    return c


@router.post("/servicenow/incidents",
             dependencies=[Depends(require_permission("itsm", "write"))])
def create_sn_incident(req: ServiceNowIncidentRequest):
    return _client().create_incident(short_description=req.short_description,
                                     description=req.description,
                                     urgency=req.urgency, impact=req.impact,
                                     assignment_group=req.assignment_group)


@router.patch("/servicenow/incidents",
              dependencies=[Depends(require_permission("itsm", "write"))])
def update_sn_incident(req: ServiceNowUpdateRequest):
    return _client().update_incident(req.sys_id, work_notes=req.work_notes, state=req.state)


@router.get("/servicenow/incidents",
            dependencies=[Depends(require_permission("itsm", "read"))])
def list_sn_incidents(query: str = "active=true", limit: int = 20):
    return _client().list_incidents(query=query, limit=limit)


@router.post("/jira/issues",
             dependencies=[Depends(require_permission("itsm", "write"))])
def create_jira_issue(req: JiraIssueRequest):
    return _client().create_issue(summary=req.summary, description=req.description,
                                  issue_type=req.issue_type, project=req.project)


@router.post("/jira/comments",
             dependencies=[Depends(require_permission("itsm", "write"))])
def add_jira_comment(req: JiraCommentRequest):
    return _client().add_comment(req.key, req.comment)


@router.post("/zendesk/tickets",
             dependencies=[Depends(require_permission("itsm", "write"))])
def create_zd_ticket(req: ZendeskTicketRequest):
    return _client().create_ticket(subject=req.subject, comment=req.comment,
                                   priority=req.priority,
                                   requester_email=req.requester_email)
