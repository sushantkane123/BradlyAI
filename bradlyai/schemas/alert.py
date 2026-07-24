"""
Pydantic Schemas for Security Alerts
"""

from pydantic import BaseModel, ConfigDict
from typing import List, Optional

class StorylineItem(BaseModel):
    time: str
    event: str
    
    model_config = ConfigDict(from_attributes=True)

class AlertBase(BaseModel):
    id: str
    severity: str
    title: str
    endpoint: str
    ip: str
    timestamp: str
    mitre: str
    status: str
    ai_confidence: str

class AlertCreate(AlertBase):
    storyline: List[StorylineItem]

class AlertResponse(AlertBase):
    storyline: List[StorylineItem]
    source: Optional[str] = None
    raw_event: Optional[str] = None
    signature: Optional[str] = None
    assigned_to: Optional[str] = None
    case_id: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)

class TriggerAttackRequest(BaseModel):
    scenario: int
