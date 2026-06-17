"""
Pydantic Schemas for Attack Surface Management (ASM) Assets
"""

from pydantic import BaseModel, ConfigDict
from typing import List

class AssetFindingSchema(BaseModel):
    finding_text: str
    
    model_config = ConfigDict(from_attributes=True)

class AssetBase(BaseModel):
    name: str
    type: str
    ip: str
    owner: str
    risk_score: str
    vulnerabilities: int
    status: str
    last_scan: str

class AssetResponse(AssetBase):
    id: int
    findings: List[str] # customized response format flattened
    
    model_config = ConfigDict(from_attributes=True)

class AssetRemediateResponse(BaseModel):
    status: str
    message: str
    asset: AssetResponse
