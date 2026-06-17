"""
FastAPI Router for AI Security Copilot
"""

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import asyncio
from cycraft.schemas.chat import ChatRequest, ChatResponse
from cycraft.services.copilot import copilot_service

router = APIRouter(prefix="/chat", tags=["AI Copilot Chatbot"])

@router.post("", response_model=ChatResponse)
def ask_copilot(req: ChatRequest):
    """
    Interact with CyCraft Cyber-AI Copilot
    """
    reply_text = copilot_service.get_reply(query=req.message)
    return ChatResponse(reply=reply_text)

@router.post("/stream")
async def ask_copilot_stream(req: ChatRequest):
    """
    Typewriter-style real-time generative streaming endpoint for AI Copilot responses
    """
    reply_text = copilot_service.get_reply(query=req.message)
    
    async def stream_generator():
        words = reply_text.split(" ")
        for word in words:
            await asyncio.sleep(0.02)
            yield f"{word} "
            
    return StreamingResponse(stream_generator(), media_type="text/plain")
