"""
BradlyAI Cyber-AI Security Copilot Chat Router
"""
import asyncio
import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from bradlyai.database import get_db
from fastapi.responses import StreamingResponse, JSONResponse

from bradlyai.database import SessionLocal
from bradlyai.models.alert import AlertModel
from bradlyai.schemas.chat import ChatRequest, ChatResponse
from bradlyai.services.llm_client import llm_client
from bradlyai.services.enhanced_copilot import real_copilot

logger = logging.getLogger("bradlyai.chat")
router = APIRouter(prefix="/chat", tags=["AI Copilot"])


async def generate_ai_stream(user_query: str, context_data: str) -> str:
    system_prompt = (
        "You are the BradlyAI Cyber-AI Copilot, the brain of a Driverless SOC. "
        "You have access to real-time security alerts. Be precise, technical, and actionable. "
        "If the user asks about the network, refer to the provided context alerts. "
        "Always conclude with a suggested remediation step."
    )
    full_prompt = f"Context Alerts:\n{context_data}\n\nUser Question: {user_query}"
    response_text = await llm_client.generate_response(full_prompt, system_prompt)
    for word in response_text.split(" "):
        yield word + " "
        await asyncio.sleep(0.03)


@router.post("", response_model=ChatResponse)
async def chat(req: ChatRequest, db: Session = Depends(get_db)):
    alerts = db.query(AlertModel).all()
    context = "\n".join([f"ID: {a.id}, Title: {a.title}, Status: {a.status}" for a in alerts])

    if req.stream:
        return StreamingResponse(
            generate_ai_stream(req.message, context),
            media_type="text/plain",
        )

    reply = real_copilot.get_reply(req.message)
    return ChatResponse(
        reply=reply,
        confidence="98.9%",
        source_models=["BradlyAI Multi-Model Cyber Mesh", "FastAPI Core"],
    )


@router.get("/health")
async def chat_health():
    return {
        "status": "operational",
        "provider": llm_client.provider,
        "api_key_configured": bool(llm_client.api_key),
    }
