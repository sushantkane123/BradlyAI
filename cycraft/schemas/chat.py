"""
Pydantic Schemas for AI Security Copilot
"""

from pydantic import BaseModel

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    reply: str
    confidence: str = "98.9%"
    source_models: list[str] = ["CyCraft Multi-Model Cyber Mesh", "FastAPI Core"]
